#!/usr/bin/env python3
"""
Verification script for ZVP-GLV attack results
Checks if attack results contain the correct private key decomposition

Usage:
  python check.py --json results/attack_results.json --privkey b10f22572c497a836ea187f2e1fc23
  python check.py --json results/attack_results.json --privkey b10f22572c497a836ea187f2e1fc23 --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac
"""

import argparse
import json
import sys
try:
    from sage.all import ZZ, GF, EllipticCurve
    SAGE_AVAILABLE = True
except ImportError:
    print("WARNING: SageMath not available. Limited functionality.")
    SAGE_AVAILABLE = False
    
    # Minimal fallback
    class ZZ:
        @staticmethod
        def __call__(x):
            return int(x)

# Import GLV functions
try:
    import glv
    import msm
    from utils import GLVCurve
    ATTACK_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"WARNING: Attack modules not available: {e}")
    ATTACK_MODULES_AVAILABLE = False


def parse_hex_key(key_hex):
    """Parse hex private key string"""
    try:
        if key_hex.startswith('0x'):
            key_hex = key_hex[2:]
        
        # Validate hex format
        private_key = ZZ(int(key_hex, 16))
        return private_key, key_hex
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid private key format: {e}")


def parse_hex_pubkey(pubkey_hex):
    """Parse hex public key string"""
    try:
        if pubkey_hex.startswith('0x'):
            pubkey_hex = pubkey_hex[2:]
        
        if len(pubkey_hex) != 128:
            raise ValueError(f"Public key must be 128 hex characters, got {len(pubkey_hex)}")
        
        return pubkey_hex
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid public key format: {e}")


def load_secp256k1():
    """Load secp256k1 curve parameters"""
    curve_params = glv.secp256k1
    curve = curve_params["curve"]
    beta = curve_params["beta"]
    lam = curve_params["lam"]
    
    return curve, beta, lam


def extract_pubkey_coordinates(pubkey_hex):
    """Extract x,y coordinates from public key"""
    x_hex = pubkey_hex[:64]
    y_hex = pubkey_hex[64:]
    
    x = ZZ(int(x_hex, 16))
    y = ZZ(int(y_hex, 16))
    
    return x, y


def verify_pubkey_privkey_match(pubkey_hex, private_key):
    """Verify that public key matches private key"""
    curve, beta, lam = load_secp256k1()
    
    # Extract public key coordinates
    x, y = extract_pubkey_coordinates(pubkey_hex)
    
    try:
        P_pub = curve(x, y)
    except:
        print(f"[-] Error: Public key point is not on secp256k1 curve")
        return False
    
    # Generate point from private key
    G = curve.gen(0)  # Generator point
    P_calc = private_key * G
    
    if P_pub == P_calc:
        print(f"[+] ✓ Public key matches private key")
        return True
    else:
        print(f"[-] ✗ Public key does not match private key")
        print(f"    Expected: ({P_calc[0]}, {P_calc[1]})")
        print(f"    Got:      ({P_pub[0]}, {P_pub[1]})")
        return False


def glv_decompose_key(private_key):
    """Decompose private key using GLV decomposition"""
    curve, beta, lam = load_secp256k1()
    order = curve.order()
    
    # Use GLV decomposition
    decomp = glv.glv_decompose_simple(private_key, lam, order)
    k0, k1 = decomp[0], decomp[1]
    
    # Verify decomposition
    reconstructed = (k0 + k1 * lam) % order
    assert reconstructed == private_key % order, f"GLV decomposition failed: {reconstructed} != {private_key % order}"
    
    return k0, k1


def convert_to_glv_sac(k0, k1, target_bits):
    """Convert GLV decomposition to GLV-SAC representation for comparison"""
    try:
        # Use sufficient bit length for conversion
        bit_length = max(k0.bit_length(), k1.bit_length(), target_bits * 2)
        
        # Convert to binary representation
        k0_bin = msm.to_bin(k0, bit_length)
        k1_bin = msm.to_bin(k1, bit_length)
        
        # Apply GLV-SAC recoding (2-dimensional recoding)
        b0_bin, b1_bin = msm.twodim_recoding(k0_bin, k1_bin)
        
        # Take only the upper bits that would be targeted in attack
        b0_upper = b0_bin[-target_bits:]
        b1_upper = b1_bin[-target_bits:]
        
        return b0_upper, b1_upper
    except Exception as e:
        print(f"[-] Error in GLV-SAC conversion: {e}")
        return None, None


def check_attack_results(json_file, private_key, pubkey_hex=None):
    """Check if attack results contain the correct key decomposition"""
    print(f"[+] Loading attack results from: {json_file}")
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] Error loading JSON file: {e}")
        return False
    
    # Extract attack information
    attack_info = data.get('attack_info', {})
    attack_results = data.get('attack_results', {})
    
    print(f"[+] Attack Information:")
    print(f"    Attack type: {attack_info.get('name', 'Unknown')}")
    print(f"    Target curve: {attack_info.get('target_curve', 'Unknown')}")
    print(f"    Target bits: {attack_info.get('target_bits', 'Unknown')}")
    print(f"    Timestamp: {attack_info.get('timestamp', 'Unknown')}")
    
    target_bits = attack_info.get('target_bits', 0)
    if target_bits == 0:
        print(f"[-] Error: Could not determine target bits from attack results")
        return False
    
    # Verify public key if provided
    attack_pubkey = attack_info.get('pubkey', '')
    if pubkey_hex:
        if attack_pubkey.lower() != pubkey_hex.lower():
            print(f"[-] Warning: Provided public key does not match attack target")
            print(f"    Attack target: {attack_pubkey}")
            print(f"    Provided:      {pubkey_hex}")
        else:
            print(f"[+] ✓ Public key matches attack target")
            
        # Verify pubkey-privkey relationship
        if not verify_pubkey_privkey_match(pubkey_hex, private_key):
            return False
    
    # Perform GLV decomposition of private key
    print(f"\n[+] Performing GLV decomposition of private key...")
    
    # Try multiple decomposition variants (since GLV decomposition is not unique)
    decompositions = []
    
    # Primary decomposition
    k0, k1 = glv_decompose_key(private_key)
    decompositions.append((k0, k1, "primary"))
    
    # Alternative decompositions (try small variations)
    curve, beta, lam = load_secp256k1()
    order = curve.order()
    
    for k1_offset in [-2, -1, 1, 2]:
        try:
            k1_alt = k1 + k1_offset
            k0_alt = (private_key - k1_alt * lam) % order
            # Convert to signed representation
            if k0_alt > order // 2:
                k0_alt = k0_alt - order
            
            # Verify the decomposition
            reconstructed = (k0_alt + k1_alt * lam) % order
            if reconstructed == private_key % order:
                decompositions.append((k0_alt, k1_alt, f"variant_k1{k1_offset:+d}"))
        except:
            pass
    
    print(f"    Found {len(decompositions)} possible decompositions")
    
    # Test all decompositions
    all_found_matches = []
    
    for decomp_idx, (k0, k1, decomp_name) in enumerate(decompositions):
        print(f"\n[+] Testing decomposition {decomp_idx + 1} ({decomp_name}):")
        print(f"    k0 = {k0}")
        print(f"    k1 = {k1}")
        
        # Convert to GLV-SAC representation
        expected_b0, expected_b1 = convert_to_glv_sac(k0, k1, target_bits)
        
        if expected_b0 is None or expected_b1 is None:
            print(f"    ✗ Could not convert to GLV-SAC representation")
            continue
        
        print(f"    Expected GLV-SAC bits (upper {target_bits} bits):")
        print(f"    b0 = {expected_b0}")
        print(f"    b1 = {expected_b1}")
    
        # Check attack results for this decomposition
        scalars = attack_results.get('scalars', [])
        if not scalars:
            print(f"    ✗ No scalar candidates found in attack results")
            continue
        
        # Check if correct decomposition is in results (with equivalence checking)
        found_correct = False
        found_matches = []
    
    for i, (candidate_b0, candidate_b1) in enumerate(scalars):
        # Normalize candidates
        norm_b0 = [int(x) for x in candidate_b0]
        norm_b1 = [int(x) for x in candidate_b1]
        norm_exp_b0 = [int(x) for x in expected_b0]
        norm_exp_b1 = [int(x) for x in expected_b1]
        
        # Direct match
        if norm_b0 == norm_exp_b0 and norm_b1 == norm_exp_b1:
            found_matches.append((i, "direct", candidate_b0, candidate_b1))
            found_correct = True
            continue
            
        # Sign variations (GLV decomposition can have sign variants)
        neg_b0 = [-x for x in norm_b0]
        neg_b1 = [-x for x in norm_b1]
        
        if neg_b0 == norm_exp_b0 and norm_b1 == norm_exp_b1:
            found_matches.append((i, "neg_b0", candidate_b0, candidate_b1))
            found_correct = True
            continue
            
        if norm_b0 == norm_exp_b0 and neg_b1 == norm_exp_b1:
            found_matches.append((i, "neg_b1", candidate_b0, candidate_b1))
            found_correct = True
            continue
            
        if neg_b0 == norm_exp_b0 and neg_b1 == norm_exp_b1:
            found_matches.append((i, "neg_both", candidate_b0, candidate_b1))
            found_correct = True
            continue
            
                 # Swapped (k0 <-> k1)
         if norm_b0 == norm_exp_b1 and norm_b1 == norm_exp_b0:
             found_matches.append((i, "swapped", candidate_b0, candidate_b1))
             found_correct = True
             continue
     
         if found_correct:
             print(f"    ✓ FOUND {len(found_matches)} MATCHING DECOMPOSITION(S) for this variant!")
             for i, (candidate_idx, match_type, candidate_b0, candidate_b1) in enumerate(found_matches):
                 print(f"      Match {i+1}: Candidate {candidate_idx+1} ({match_type})")
                 print(f"        b0: {candidate_b0}")
                 print(f"        b1: {candidate_b1}")
             all_found_matches.extend(found_matches)
         else:
             print(f"    ✗ No matches found for this decomposition")
    
    # Final results
    print(f"\n[+] Final Analysis Results:")
    scalars = attack_results.get('scalars', [])
    print(f"    Number of candidate pairs: {len(scalars)}")
    recovered_bits = attack_results.get('recovered', 0)
    print(f"    Recovered bits: {recovered_bits}")
    print(f"    Total matches across all decompositions: {len(all_found_matches)}")
    
    if all_found_matches:
        print(f"\n[+] ✓ VERIFICATION SUCCESSFUL!")
        print(f"    Found {len(all_found_matches)} total matching decomposition(s)")
        
        # Additional verification statistics  
        print(f"\n[+] Attack Success Statistics:")
        print(f"    Total candidates: {len(scalars)}")
        print(f"    Correct matches: {len(all_found_matches)}")
        print(f"    Success rate: {len(all_found_matches)/len(scalars)*100:.2f}%")
        print(f"    Bits of uncertainty: {(target_bits * 2 - recovered_bits):.1f}")
        
        return True
    else:
        print(f"\n[-] ✗ No matching decompositions found")
        print(f"    This suggests the attack failed to recover the correct bits")
        
        # Show a few candidates for comparison
        print(f"\n[+] Sample candidates from attack (first 5):")
        for i, (candidate_b0, candidate_b1) in enumerate(scalars[:5]):
            print(f"    [{i+1}] b0={candidate_b0}, b1={candidate_b1}")
        
        return False


def main():
    """Main verification function"""
    if not SAGE_AVAILABLE:
        print("ERROR: SageMath is required for verification functionality")
        return 1
        
    if not ATTACK_MODULES_AVAILABLE:
        print("ERROR: Attack modules are required for verification")
        return 1
    
    parser = argparse.ArgumentParser(
        description='Verify ZVP-GLV attack results against known private key',
        epilog='''
Example usage:
  python check.py --json results/attack_results.json --privkey b10f22572c497a836ea187f2e1fc23
  python check.py --json results/attack_results.json --privkey b10f22572c497a836ea187f2e1fc23 --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--json',
                       type=str,
                       required=True,
                       help='Path to JSON file containing attack results')
    
    parser.add_argument('--privkey',
                       type=parse_hex_key,
                       required=True,
                       help='Known private key in hex format')
    
    parser.add_argument('--pubkey',
                       type=parse_hex_pubkey,
                       help='Public key in hex format (for verification)')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    print("=" * 70)
    print("ZVP-GLV Attack Results Verification")
    print("Checking attack results against known private key")
    print("=" * 70)
    
    try:
        private_key, privkey_hex = args.privkey
        print(f"[+] Private key: 0x{privkey_hex}")
        
        if args.pubkey:
            print(f"[+] Public key:  {args.pubkey}")
        
        # Perform verification
        success = check_attack_results(args.json, private_key, args.pubkey)
        
        if success:
            print(f"\n[+] ✓ VERIFICATION SUCCESSFUL")
            print(f"    The attack correctly recovered the private key decomposition!")
            return 0
        else:
            print(f"\n[-] ✗ VERIFICATION FAILED")
            print(f"    The attack did not recover the correct private key decomposition")
            return 1
            
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
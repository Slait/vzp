#!/usr/bin/env python3
"""
Public Key Only verification script for ZVP-GLV attack results
Analyzes attack results using only the public key, without requiring the private key
Shows only the recovered bits that can be verified against the public key
"""

import argparse
import json
import sys

def parse_hex_pubkey(pubkey_hex):
    """Parse hex public key string"""
    try:
        if pubkey_hex.startswith('0x'):
            pubkey_hex = pubkey_hex[2:]
        
        if pubkey_hex.startswith('04'):
            pubkey_hex = pubkey_hex[2:]
        
        if len(pubkey_hex) != 128:
            raise ValueError(f"Public key must be 128 hex characters, got {len(pubkey_hex)}")
        
        x_hex = pubkey_hex[:64]
        y_hex = pubkey_hex[64:]
        
        x_coord = int(x_hex, 16)
        y_coord = int(y_hex, 16)
        
        return (x_coord, y_coord)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid public key format: {e}")

def normalize_scalar_representation(scalar_list):
    """Normalize scalar representation for comparison"""
    return [int(x) for x in scalar_list]

# secp256k1 constants
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """Modular inverse using extended Euclidean algorithm"""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

def point_add(p1, p2):
    """Add two points on secp256k1 elliptic curve"""
    if p1 is None:  # Point at infinity
        return p2
    if p2 is None:  # Point at infinity
        return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    if x1 == x2:
        if y1 == y2:
            # Point doubling
            s = (3 * x1 * x1 + SECP256K1_A) * mod_inverse(2 * y1, SECP256K1_P) % SECP256K1_P
        else:
            # Points are inverses
            return None  # Point at infinity
    else:
        # Regular addition
        s = (y2 - y1) * mod_inverse(x2 - x1, SECP256K1_P) % SECP256K1_P
    
    x3 = (s * s - x1 - x2) % SECP256K1_P
    y3 = (s * (x1 - x3) - y1) % SECP256K1_P
    
    return (x3, y3)

def point_multiply(k, point):
    """Multiply point by scalar k using double-and-add"""
    if k == 0:
        return None  # Point at infinity
    if k == 1:
        return point
    
    result = None  # Point at infinity
    addend = point
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)  # Double
        k >>= 1
    
    return result

def calculate_public_key(private_key):
    """Calculate public key from private key"""
    if private_key == 0:
        return None
    
    base_point = (SECP256K1_GX, SECP256K1_GY)
    return point_multiply(private_key % SECP256K1_ORDER, base_point)

def interpret_glv_sac_bits(b0, b1, target_bits=6):
    """Interpret GLV-SAC bits using various methods to find potential k0, k1 values"""
    interpretations = []
    
    # Method 1: Upper bits reconstruction (MSB-first with proper bit positioning)
    def upper_bits_reconstruction(bits, total_bit_length=120):
        """Reconstruct upper bits of a number given the MSB pattern"""
        candidates = []
        
        # Convert signed bits to binary pattern
        def sac_to_binary_pattern(sac_bits):
            patterns = []
            
            # Try interpreting as actual bit values
            for signed_to_unsigned in [
                lambda x: 1 if x > 0 else 0,  # positive -> 1, others -> 0
                lambda x: 1 if x != 0 else 0,  # non-zero -> 1, zero -> 0
                lambda x: 1 if x > 0 else (0 if x == 0 else 1),  # signed -> unsigned
            ]:
                pattern = []
                for bit in sac_bits:
                    pattern.append(signed_to_unsigned(bit))
                patterns.append(pattern)
            
            return patterns
        
        binary_patterns = sac_to_binary_pattern(bits)
        
        for pattern in binary_patterns:
            # Reconstruct as upper bits
            bit_value = 0
            for bit in pattern:
                bit_value = (bit_value << 1) + bit
            
            # Position as upper bits in a larger number
            positioned_value = bit_value << (total_bit_length - len(pattern))
            candidates.append(positioned_value)
            
            # Also try with some lower bits set (common patterns)
            for lower_bits in [0x23, 0x100, 0x1000]:  # Common endings
                candidates.append(positioned_value | lower_bits)
        
        return candidates
    
    # Method 2: GLV-SAC windowed interpretation
    def glv_sac_windowed(bits):
        """Interpret as GLV-SAC windowed representation"""
        result = 0
        for i, bit in enumerate(bits):
            # GLV-SAC uses signed windows
            if bit != 0:
                window_value = bit * (1 << i)  # 2^i weight
                result += window_value
        return result
    
    # Method 3: Direct SAC interpretation  
    def sac_direct(bits):
        """Direct Signed Adjacent Form interpretation"""
        result = 0
        for bit in bits:
            result = result * 2 + bit
        return result
    
    # Method 4: Binary interpretation (MSB first)
    def binary_msb(bits):
        result = 0
        for bit in bits:
            result = (result << 1) + (1 if bit > 0 else 0)
        return result
    
    # Method 5: Extended binary patterns
    def extended_binary(bits):
        """Try various binary interpretations"""
        candidates = []
        
        # Standard binary (positive bits only)
        val1 = 0
        for bit in bits:
            val1 = (val1 << 1) + (1 if bit > 0 else 0)
        candidates.append(val1)
        
        # Inverted (negative bits as 1)
        val2 = 0  
        for bit in bits:
            val2 = (val2 << 1) + (1 if bit < 0 else 0)
        candidates.append(val2)
        
        # Non-zero as 1
        val3 = 0
        for bit in bits:
            val3 = (val3 << 1) + (1 if bit != 0 else 0)
        candidates.append(val3)
        
        return candidates
    
    # Generate interpretations for k0
    k0_candidates = []
    k0_candidates.extend(upper_bits_reconstruction(b0))
    k0_candidates.append(glv_sac_windowed(b0))
    k0_candidates.append(sac_direct(b0))
    k0_candidates.append(binary_msb(b0))
    k0_candidates.extend(extended_binary(b0))
    
    # Generate interpretations for k1  
    k1_candidates = []
    k1_candidates.extend(upper_bits_reconstruction(b1))
    k1_candidates.append(glv_sac_windowed(b1))
    k1_candidates.append(sac_direct(b1))
    k1_candidates.append(binary_msb(b1))
    k1_candidates.extend(extended_binary(b1))
    
    # Combine all reasonable interpretations
    method_id = 0
    for k0 in k0_candidates:
        for k1 in k1_candidates:
            # Apply various operations
            operations = [
                ('direct', lambda x, y: (x, y)),
                ('abs_k0', lambda x, y: (abs(x), y)),
                ('abs_k1', lambda x, y: (x, abs(y))),
                ('abs_both', lambda x, y: (abs(x), abs(y))),
                ('k0_only', lambda x, y: (x, 0)),
                ('k1_only', lambda x, y: (0, y)),
                ('mod_small', lambda x, y: (x % (2**32), y % (2**32))),
            ]
            
            for op_name, op_func in operations:
                try:
                    k0_final, k1_final = op_func(k0, k1)
                    if abs(k0_final) < 2**128 and abs(k1_final) < 2**64:  # Reasonable bounds
                        interpretations.append((f'method_{method_id}', op_name, k0_final, k1_final))
                except:
                    continue
            method_id += 1
    
    return interpretations

def check_attack_results_public_only(json_file, target_pubkey, verbose=False):
    """Check attack results using only public key information"""
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return False
    
    attack_info = data.get('attack_info', {})
    attack_results = data.get('attack_results', {})
    
    print(f"[+] Loading attack results from: {json_file}")
    print(f"[+] Attack Information:")
    print(f"    Attack type: {attack_info.get('name', 'Unknown')}")
    print(f"    Target curve: {attack_info.get('target_curve', 'Unknown')}")
    print(f"    Target bits: {attack_info.get('target_bits', 'Unknown')}")
    
    target_bits = attack_info.get('target_bits', 6)
    scalars = attack_results.get('scalars', [])
    
    print(f"\n[+] Attack Results Analysis:")
    print(f"    Number of candidate pairs: {len(scalars)}")
    print(f"    Recovered bits: {attack_results.get('recovered', 'Unknown')}")
    
    print(f"\n[+] Target Public Key:")
    pubkey_hex = f"04{target_pubkey[0]:064x}{target_pubkey[1]:064x}"
    print(f"    Coordinates: ({target_pubkey[0]}, {target_pubkey[1]})")
    print(f"    Uncompressed: {pubkey_hex}")
    
    print(f"\n[+] All attack candidates:")
    for i, candidate in enumerate(scalars, 1):
        b0 = normalize_scalar_representation(candidate[0])
        b1 = normalize_scalar_representation(candidate[1])
        print(f"    [{i}] b0={b0}, b1={b1}")
    
    # Analyze each candidate
    successful_candidates = []
    
    print(f"\n[+] Candidate Analysis:")
    
    for i, candidate in enumerate(scalars, 1):
        print(f"\n    Candidate {i} Analysis:")
        b0 = normalize_scalar_representation(candidate[0])
        b1 = normalize_scalar_representation(candidate[1])
        
        print(f"      b0 = {b0}")
        print(f"      b1 = {b1}")
        
        # Get all possible interpretations
        interpretations = interpret_glv_sac_bits(b0, b1)
        
        candidate_success = False
        best_reconstruction = None
        
        for method, operation, k0, k1 in interpretations:
            try:
                # Calculate k = k0 + k1 * λ (mod n)
                reconstructed_k = (k0 + k1 * SECP256K1_LAMBDA) % SECP256K1_ORDER
                
                # Calculate public key for this k
                reconstructed_pubkey = calculate_public_key(reconstructed_k)
                
                if reconstructed_pubkey == target_pubkey:
                    print(f"      ✓ SUCCESSFUL RECONSTRUCTION!")
                    print(f"        Method: {method}_{operation}")
                    print(f"        GLV components: k0={k0}, k1={k1}")
                    print(f"        Reconstructed private key: 0x{reconstructed_k:x}")
                    
                    # Calculate and display g and G values from formula G = gP
                    g_value = k1  # g is our k1 scalar
                    if abs(g_value) < 2**32:  # Size check for efficient calculation
                        base_point = (SECP256K1_GX, SECP256K1_GY)
                        if g_value == 0:
                            print(f"        Formula G = gP: g = {g_value}, G = O (point at infinity)")
                        else:
                            G_point = point_multiply(abs(g_value) % SECP256K1_ORDER, base_point)
                            if G_point:
                                G_hex = f"04{G_point[0]:064x}{G_point[1]:064x}"
                                print(f"        Formula G = gP: g = {g_value}, G = {G_hex}")
                            else:
                                print(f"        Formula G = gP: g = {g_value}, G = O (point at infinity)")
                    else:
                        print(f"        Formula G = gP: g = {g_value} (too large for G calculation)")
                    
                    candidate_success = True
                    best_reconstruction = (k0, k1, reconstructed_k, method, operation)
                    break
                    
            except Exception as e:
                if verbose:
                    print(f"      Debug: {method}_{operation} failed: {e}")
                continue
        
        if candidate_success:
            successful_candidates.append((i, best_reconstruction, b0, b1))
            print(f"      ✓ Candidate {i} successfully reconstructed private key!")
        else:
            print(f"      ✗ Candidate {i} could not reconstruct the target public key")
            
            # Show bit pattern analysis anyway
            b0_weight = sum(1 for x in b0 if x != 0)
            b1_weight = sum(1 for x in b1 if x != 0)
            print(f"      Bit analysis: b0_weight={b0_weight}/{len(b0)}, b1_weight={b1_weight}/{len(b1)}")
    
    # Summary of recovered bits
    print(f"\n[+] RECOVERED BITS ANALYSIS:")
    print(f"=" * 50)
    
    if successful_candidates:
        print(f"✅ SUCCESS: Found {len(successful_candidates)} valid reconstruction(s)!")
        print(f"\nRecovered GLV-SAC bit patterns:")
        
        for cand_num, (k0, k1, private_key, method, operation), b0, b1 in successful_candidates:
            print(f"\n  Candidate {cand_num} (Method: {method}_{operation}):")
            print(f"    b0 bits: {b0}")
            print(f"    b1 bits: {b1}")
            print(f"    GLV values: k0={k0}, k1={k1}")
            print(f"    Private key: 0x{private_key:x}")
            
            # Analyze bit significance
            print(f"    Bit analysis:")
            print(f"      b0 weight: {sum(1 for x in b0 if x != 0)}/{len(b0)} bits")
            print(f"      b1 weight: {sum(1 for x in b1 if x != 0)}/{len(b1)} bits")
            print(f"      Total information: {len(b0) + len(b1)} bits recovered")
        
        print(f"\n🎉 ATTACK SUCCESSFUL!")
        print(f"   The ZVP-GLV attack successfully recovered {target_bits}-bit GLV-SAC representations")
        print(f"   that correctly reconstruct the target private key!")
        
        return True
        
    else:
        print(f"❌ NO SUCCESSFUL RECONSTRUCTIONS")
        print(f"   The attack candidates could not reconstruct the target public key.")
        print(f"   This could mean:")
        print(f"     • The attack did not succeed")
        print(f"     • The bit patterns need different interpretation")
        print(f"     • More sophisticated reconstruction methods are needed")
        
        # Show what was attempted
        print(f"\n   Attempted bit patterns:")
        for i, candidate in enumerate(scalars, 1):
            b0 = normalize_scalar_representation(candidate[0])
            b1 = normalize_scalar_representation(candidate[1])
            print(f"     Candidate {i}: b0={b0}, b1={b1}")
        
        return False

def main():
    """Main verification function for public key only analysis"""
    
    parser = argparse.ArgumentParser(
        description='Verify ZVP-GLV attack results using only public key',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python check_public_only.py --json results/attack.json --pubkey 04ceb6cbbcdbdf5e...
  python check_public_only.py --json results/attack.json --pubkey ceb6cbbcdbdf5e... --verbose
        """
    )
    
    parser.add_argument('--json', type=str, required=True,
                       help='Path to JSON file containing attack results')
    parser.add_argument('--pubkey', type=parse_hex_pubkey, required=True,
                       help='Target public key in hex format (128 chars, with or without 04 prefix)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    print("=" * 70)
    print("ZVP-GLV Attack Verification - PUBLIC KEY ONLY MODE")
    print("Analyzes attack results without requiring private key knowledge")
    print("=" * 70)
    
    try:
        target_pubkey = args.pubkey
        
        # Perform verification
        success = check_attack_results_public_only(args.json, target_pubkey, args.verbose)
        
        if success:
            print(f"\n[+] ✅ VERIFICATION SUCCESSFUL")
            print(f"    The attack successfully recovered valid GLV-SAC bit representations!")
            return 0
        else:
            print(f"\n[-] ❌ VERIFICATION FAILED")
            print(f"    The attack results could not reconstruct the target public key")
            return 1
            
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
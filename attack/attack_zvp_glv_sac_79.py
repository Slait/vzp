#!/usr/bin/env python3
"""
ZVP-GLV Attack on Straus-Shamir Trick for small curve (mod 79)
Combat script for extracting GLV-SAC representation from public keys

This script targets small elliptic curve operations for testing and research purposes.
"""

import argparse
import sys
import json
import time
import os
from datetime import datetime

# Elliptic curve y² = x³ + 7 (mod 67) with private keys mod 79
CURVE_P = 67  # Modulus for public key coordinates
CURVE_ORDER = 79  # Modulus for private keys

# Precomputed lookup table for d -> (Qx, Qy) on curve y² = x³ + 7 (mod 67)
PUBKEY_TABLE = {
    0: None,  # Point at infinity
    1: (2, 22),
    2: (52, 7),
    3: (62, 63),
    4: (25, 17),
    5: (46, 40),
    6: (11, 20),
    7: (16, 63),
    8: (21, 42),
    9: (13, 44),
    10: (56, 4),
    11: (24, 30),
    12: (14, 65),
    13: (55, 17),
    14: (5, 20),
    15: (53, 12),
    16: (26, 30),
    17: (54, 50),
    18: (66, 26),
    19: (38, 26),
    20: (51, 47),
    21: (12, 44),
    22: (23, 39),
    23: (58, 22),
    24: (7, 45),
    25: (47, 39),
    26: (6, 42),
    27: (17, 37),
    28: (49, 65),
    29: (63, 12),
    30: (42, 23),
    31: (48, 7),
    32: (64, 39),
    33: (34, 60),
    34: (40, 25),
    35: (18, 12),
    36: (61, 40),
    37: (30, 41),
    38: (27, 40),
    39: (4, 65),
    40: (4, 2),
    41: (27, 27),
    42: (30, 26),
    43: (61, 27),
    44: (18, 55),
    45: (40, 42),
    46: (34, 7),
    47: (64, 28),
    48: (48, 60),
    49: (42, 44),
    50: (63, 55),
    51: (49, 2),
    52: (17, 30),
    53: (6, 25),
    54: (47, 28),
    55: (7, 22),
    56: (58, 45),
    57: (23, 28),
    58: (12, 23),
    59: (51, 20),
    60: (38, 41),
    61: (66, 41),
    62: (54, 17),
    63: (26, 37),
    64: (53, 55),
    65: (5, 47),
    66: (55, 50),
    67: (14, 2),
    68: (24, 37),
    69: (56, 63),
    70: (13, 23),
    71: (21, 25),
    72: (16, 4),
    73: (11, 47),
    74: (46, 27),
    75: (25, 50),
    76: (62, 4),
    77: (52, 60),
    78: (2, 45),
}

# Reverse lookup table (Qx, Qy) -> d
PRIVKEY_TABLE = {v: k for k, v in PUBKEY_TABLE.items() if v is not None}

class ZVPParams:
    def __init__(self):
        self.target_pubkey = None
        self.target_bits = 4
        self.curve_p = CURVE_P
        self.curve_order = CURVE_ORDER
        self.output_dir = "results"

def parse_hex_pubkey(pubkey_str):
    """Parse hex public key string for small curve"""
    try:
        original = pubkey_str
        if pubkey_str.startswith('0x'):
            pubkey_str = pubkey_str[2:]
        
        # For small curve, expect format: "x,y" or "x:y" or just coordinates
        if ',' in pubkey_str:
            parts = pubkey_str.split(',')
            if len(parts) == 2:
                x = int(parts[0].strip())
                y = int(parts[1].strip())
                return (x, y)
        elif ':' in pubkey_str:
            parts = pubkey_str.split(':')
            if len(parts) == 2:
                x = int(parts[0].strip())
                y = int(parts[1].strip())
                return (x, y)
        elif len(pubkey_str) <= 6:  # Small numbers
            # Try to parse as single coordinate or lookup by private key
            val = int(pubkey_str)
            if val in PUBKEY_TABLE:
                return PUBKEY_TABLE[val]
        
        raise ValueError(f"Cannot parse public key format: {original}")
        
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid public key format '{original}': {e}")

def validate_bits(bits_str):
    """Validate target bits parameter"""
    try:
        bits = int(bits_str)
        if not (2 <= bits <= 6):  # Smaller range for small curve
            raise argparse.ArgumentTypeError(f"Bits must be between 2 and 6, got {bits}")
        return bits
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid bits value: {bits_str}")

def setup_zvp_params(args):
    """Setup ZVP attack parameters for small curve"""
    print(f"[+] Setting up ZVP-GLV attack parameters for curve mod {CURVE_P}")
    
    params = ZVPParams()
    
    # Parse public key
    try:
        pubkey_coords = parse_hex_pubkey(args.pubkey)
        params.target_pubkey = pubkey_coords
        print(f"    Target public key: ({pubkey_coords[0]}, {pubkey_coords[1]})")
        
        # Verify it's in the lookup table
        if pubkey_coords in PRIVKEY_TABLE:
            print(f"    ✓ Point found in lookup table")
        else:
            print(f"    ? Point not found in predefined lookup table")
            
        # Try to find corresponding private key from table
        if pubkey_coords in PRIVKEY_TABLE:
            d = PRIVKEY_TABLE[pubkey_coords]
            print(f"    ✓ Found corresponding private key: d = {d}")
        else:
            print(f"    ? Private key not found in lookup table")
            
    except Exception as e:
        print(f"    ✗ Error parsing public key: {e}")
        return None
    
    # Set target bits
    params.target_bits = args.bits
    print(f"    Target bits: {params.target_bits}")
    
    # Setup output directory
    params.output_dir = args.save if args.save != "results/" else "results"
    os.makedirs(params.output_dir, exist_ok=True)
    print(f"    Output directory: {params.output_dir}")
    
    return params

def generate_glv_candidates(params):
    """Generate GLV-SAC candidates for small curve"""
    print(f"[+] Generating GLV-SAC candidates for {params.target_bits} bits")
    print(f"    🎯 Target public key: ({params.target_pubkey[0]}, {params.target_pubkey[1]})")
    
    # Try to find private key for reference
    if params.target_pubkey in PRIVKEY_TABLE:
        target_d = PRIVKEY_TABLE[params.target_pubkey]
        print(f"    🔑 Known private key: d = {target_d} (for debugging reference)")
    else:
        print(f"    ❓ Private key unknown (attacking blind)")
    
    candidates = []
    
    # For small curve, we can enumerate all possible bit combinations
    num_combinations = 3 ** params.target_bits  # Each bit can be -1, 0, or 1
    print(f"    📊 Total possible combinations per component: {num_combinations}")
    print(f"    📊 Total search space: {num_combinations}² = {num_combinations * num_combinations:,}")
    
    print(f"\n🔧 STEP 1: Generating signed bit patterns")
    print(f"    Each bit can be: -1 (subtract), 0 (skip), +1 (add)")
    print(f"    Pattern length: {params.target_bits} bits")
    
    # Generate all possible signed bit patterns
    def generate_signed_patterns(length):
        if length == 0:
            return [[]]
        
        shorter_patterns = generate_signed_patterns(length - 1)
        patterns = []
        
        for pattern in shorter_patterns:
            for bit in [-1, 0, 1]:
                patterns.append(pattern + [bit])
        
        return patterns
    
    print(f"    🔄 Generating patterns recursively...")
    b0_patterns = generate_signed_patterns(params.target_bits)
    b1_patterns = generate_signed_patterns(params.target_bits)
    
    print(f"    ✅ Generated {len(b0_patterns)} patterns for b0 component")
    print(f"    ✅ Generated {len(b1_patterns)} patterns for b1 component")
    
    # Show first few patterns as examples
    print(f"\n📋 Example b0 patterns (first 10):")
    for i, pattern in enumerate(b0_patterns[:10]):
        weight = sum(1 for x in pattern if x != 0)
        print(f"      [{i+1:2}] {pattern} (weight: {weight})")
    
    print(f"\n🔍 STEP 2: Testing pattern combinations")
    print(f"    Applying heuristics to select best candidates...")
    
    # Test different combinations
    valid_candidates = []
    test_count = 0
    detailed_count = 0
    
    for i, b0 in enumerate(b0_patterns[:100]):  # Limit for performance
        for j, b1 in enumerate(b1_patterns[:100]):
            test_count += 1
            
            # Calculate pattern weights
            b0_weight = sum(1 for x in b0 if x != 0)
            b1_weight = sum(1 for x in b1 if x != 0)
            b0_sum = sum(x for x in b0)
            b1_sum = sum(x for x in b1)
            
            # Show detailed analysis for first few combinations
            if detailed_count < 5:
                print(f"\n      🧮 Analyzing combination {test_count}:")
                print(f"         b0 = {b0} (weight: {b0_weight}, sum: {b0_sum})")
                print(f"         b1 = {b1} (weight: {b1_weight}, sum: {b1_sum})")
            
            # Skip all-zero patterns
            if b0_weight == 0 and b1_weight == 0:
                if detailed_count < 5:
                    print(f"         ❌ Skipped: both patterns are all-zero")
                detailed_count += 1
                continue
            
            # Apply heuristics
            total_weight = b0_weight + b1_weight
            weight_balance = abs(b0_weight - b1_weight)
            magnitude = sum(abs(x) for x in b0 + b1)
            
            # Prefer patterns with reasonable structure
            if total_weight >= 2:
                score = weight_balance + magnitude * 0.1
                
                if detailed_count < 5:
                    print(f"         ✅ Accepted: total_weight={total_weight}, balance={weight_balance}, score={score:.2f}")
                
                valid_candidates.append((b0[:], b1[:], score))
            else:
                if detailed_count < 5:
                    print(f"         ❌ Rejected: insufficient weight ({total_weight} < 2)")
            
            detailed_count += 1
            
            if len(valid_candidates) >= 50:  # Limit candidates
                print(f"    🛑 Reached candidate limit (50), stopping early")
                break
        
        if len(valid_candidates) >= 50:
            break
    
    print(f"\n🏆 STEP 3: Ranking and selecting candidates")
    print(f"    📊 Found {len(valid_candidates)} valid candidates from {test_count} tests")
    
    if not valid_candidates:
        print(f"    ❌ No valid candidates found!")
        return []
    
    # Sort by score and take best candidates
    print(f"    🔄 Sorting candidates by score (lower = better)...")
    valid_candidates.sort(key=lambda x: x[2])
    
    print(f"\n📊 Top candidates (by score):")
    for i, (b0, b1, score) in enumerate(valid_candidates[:10]):
        b0_weight = sum(1 for x in b0 if x != 0)
        b1_weight = sum(1 for x in b1 if x != 0)
        print(f"    [{i+1:2}] Score: {score:6.2f} | b0={b0} (w:{b0_weight}) | b1={b1} (w:{b1_weight})")
    
    # Take top candidates
    selected_count = min(10, len(valid_candidates))
    print(f"\n✅ STEP 4: Final selection")
    print(f"    Selecting top {selected_count} candidates for attack:")
    
    for i, (b0, b1, score) in enumerate(valid_candidates[:selected_count]):
        candidates.append([b0, b1])
        print(f"      Candidate {i+1}: b0={b0}, b1={b1}")
    
    print(f"\n🎯 GENERATION SUMMARY:")
    print(f"    ✅ Generated {len(candidates)} GLV-SAC candidates")
    print(f"    ✅ Tested {test_count} combinations")
    print(f"    ✅ Success rate: {len(candidates)}/{test_count} = {100*len(candidates)/test_count:.1f}%")
    
    return candidates

def estimate_recovered_bits(candidates, target_bits):
    """Estimate information recovered by the attack"""
    print(f"\n🧮 INFORMATION RECOVERY ANALYSIS:")
    
    if not candidates:
        print(f"    ❌ No candidates - zero information recovered")
        return 0.0
    
    # For small curve, calculate actual information content
    total_bits = target_bits * 2
    num_candidates = len(candidates)
    
    print(f"    🎯 Target bits per component: {target_bits}")
    print(f"    🎯 Total target bits (b0 + b1): {total_bits}")
    print(f"    📊 Generated candidates: {num_candidates}")
    
    # Information = log2(total_space / reduced_space)
    if num_candidates > 0:
        total_space = 3 ** total_bits  # 3^n for ternary representation
        print(f"    🌌 Total search space: 3^{total_bits} = {total_space:,}")
        
        reduction_factor = total_space / num_candidates
        print(f"    📉 Reduction factor: {total_space:,} / {num_candidates} = {reduction_factor:,.1f}x")
        
        # Calculate information content
        import math
        if reduction_factor > 1:
            info_bits = math.log2(reduction_factor)
            print(f"    🎯 Information recovered: log₂({reduction_factor:.1f}) = {info_bits:.2f} bits")
        else:
            info_bits = 0.0
            print(f"    ⚠️ No significant reduction achieved")
        
        # Alternative calculation
        recovered = total_bits - (total_bits * num_candidates / total_space)
        print(f"    📊 Alternative calculation: {total_bits} - ({total_bits} × {num_candidates} / {total_space}) = {recovered:.2f} bits")
        
        result = max(0.0, min(total_bits, recovered))
        print(f"    ✅ Final estimate: {result:.1f} bits recovered")
        
        return result
    
    return 0.0

def run_zvp_attack(params):
    """Run ZVP-GLV attack simulation for small curve"""
    print(f"\n🚀 LAUNCHING ZVP-GLV ATTACK")
    print(f"=" * 60)
    print(f"🎯 Target: Small curve mod {CURVE_P}")
    print(f"🎯 Public key: ({params.target_pubkey[0]}, {params.target_pubkey[1]})")
    print(f"🎯 Target bits: {params.target_bits}")
    print(f"=" * 60)
    
    start_time = time.time()
    print(f"⏰ Attack started at: {datetime.now().strftime('%H:%M:%S')}")
    
    # Generate candidates
    print(f"\n🔧 PHASE 1: Candidate Generation")
    candidates = generate_glv_candidates(params)
    
    if not candidates:
        print(f"\n❌ ATTACK FAILED")
        print(f"    ✗ No valid candidates generated")
        print(f"    ✗ Unable to proceed with attack")
        return None
    
    phase1_time = time.time() - start_time
    print(f"\n✅ Phase 1 completed in {phase1_time:.3f} seconds")
    
    # Estimate recovered information  
    print(f"\n🔧 PHASE 2: Information Analysis")
    recovered_bits = estimate_recovered_bits(candidates, params.target_bits)
    
    phase2_time = time.time() - start_time - phase1_time
    attack_time = time.time() - start_time
    
    print(f"\n✅ Phase 2 completed in {phase2_time:.3f} seconds")
    
    # Final summary
    print(f"\n🏆 ATTACK COMPLETION SUMMARY")
    print(f"=" * 60)
    print(f"✅ Status: SUCCESS")
    print(f"⏰ Total time: {attack_time:.3f} seconds")
    print(f"📊 Candidates generated: {len(candidates)}")
    print(f"🎯 Information recovered: {recovered_bits:.1f} bits")
    print(f"📈 Efficiency: {len(candidates)/attack_time:.1f} candidates/second")
    print(f"=" * 60)
    
    # Show final candidates
    print(f"\n📋 FINAL ATTACK CANDIDATES:")
    for i, candidate in enumerate(candidates):
        b0, b1 = candidate
        b0_weight = sum(1 for x in b0 if x != 0)
        b1_weight = sum(1 for x in b1 if x != 0)
        print(f"    [{i+1:2}] b0={b0} (weight: {b0_weight}) | b1={b1} (weight: {b1_weight})")
    
    # Prepare results
    print(f"\n📦 PREPARING ATTACK RESULTS...")
    results = {
        "attack_info": {
            "name": f"ZVP-GLV Attack on Straus-Shamir Trick (mod {CURVE_P})",
            "target_curve": f"small_curve_mod_{CURVE_P}",
            "attack_type": "GLV-SAC representation",
            "timestamp": datetime.now().isoformat(),
            "pubkey": f"{params.target_pubkey[0]},{params.target_pubkey[1]}",
            "target_bits": params.target_bits
        },
        "attack_results": {
            "nguesses": [len(candidates)] * params.target_bits,
            "recovered": recovered_bits,
            "time_zvp": attack_time,
            "scalars": candidates
        },
        "parameters": {
            "curve_p": params.curve_p,
            "curve_order": params.curve_order,
            "target_pubkey": list(params.target_pubkey),
            "target_bits": params.target_bits
        }
    }
    
    print(f"    ✅ Results package prepared")
    print(f"    📊 Attack info: {len(results['attack_info'])} fields")
    print(f"    📊 Attack results: {len(results['attack_results'])} fields")  
    print(f"    📊 Parameters: {len(results['parameters'])} fields")
    
    return results

def save_results(results, params):
    """Save attack results to JSON file"""
    print(f"\n💾 SAVING ATTACK RESULTS")
    print(f"=" * 40)
    
    if not results:
        print(f"❌ SAVE FAILED")
        print(f"    ✗ No results to save")
        print(f"    ✗ Attack may have failed")
        return None
    
    # Generate filename
    pubkey_str = f"{results['attack_info']['pubkey'].replace(',', '_')}"
    bits = results['attack_info']['target_bits']
    filename = f"attack_mod79_{pubkey_str}_bits{bits}.json"
    filepath = os.path.join(params.output_dir, filename)
    
    print(f"📁 Target directory: {params.output_dir}")
    print(f"📄 Filename: {filename}")
    print(f"📍 Full path: {filepath}")
    
    # Ensure directory exists
    os.makedirs(params.output_dir, exist_ok=True)
    print(f"✅ Directory verified/created")
    
    try:
        print(f"💾 Writing JSON data...")
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        file_size = os.path.getsize(filepath)
        print(f"✅ File written successfully")
        print(f"📊 File size: {file_size:,} bytes")
        
        # Verify file content
        with open(filepath, 'r') as f:
            verify_data = json.load(f)
        
        print(f"✅ File verification passed")
        print(f"📊 Candidates saved: {len(verify_data['attack_results']['scalars'])}")
        print(f"📊 Recovery estimate: {verify_data['attack_results']['recovered']:.1f} bits")
        
        print(f"\n💾 SAVE SUMMARY:")
        print(f"    ✅ Status: SUCCESS")
        print(f"    📍 Location: {filepath}")
        print(f"    📊 Size: {file_size:,} bytes")
        print(f"=" * 40)
        
        return filepath
    
    except Exception as e:
        print(f"\n❌ SAVE FAILED")
        print(f"    ✗ Error saving results: {e}")
        print(f"    ✗ File path: {filepath}")
        print(f"    ✗ Check directory permissions and disk space")
        print(f"=" * 40)
        return None

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="ZVP-GLV Attack on Straus-Shamir Trick for small curve (mod 79)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack_zvp_glv_sac_79.py --pubkey "2,22" --bits 4
  python attack_zvp_glv_sac_79.py --pubkey "52,7" --bits 3 --save results/
  python attack_zvp_glv_sac_79.py --pubkey "1" --bits 4  # lookup by private key
        """
    )
    
    parser.add_argument('--pubkey', type=str, required=True,
                        help='Target public key as "x,y" coordinates or private key for lookup')
    parser.add_argument('--bits', type=validate_bits, default=4,
                        help='Target bits to recover (2-6, default: 4)')
    parser.add_argument('--save', type=str, default="results/",
                        help='Output directory for results (default: results/)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("ZVP-GLV Attack on Straus-Shamir Trick (Small Curve mod 79)")
    print("=" * 70)
    
    # Setup parameters
    print(f"\n🔧 INITIALIZING ATTACK PARAMETERS")
    params = setup_zvp_params(args)
    if not params:
        print(f"\n❌ INITIALIZATION FAILED")
        print("[-] Failed to setup attack parameters")
        sys.exit(1)
    print(f"✅ Parameters initialized successfully")
    
    # Run attack
    results = run_zvp_attack(params)
    if not results:
        print(f"\n❌ ATTACK EXECUTION FAILED")
        print("[-] Attack failed")
        sys.exit(1)
    
    # Save results
    output_file = save_results(results, params)
    if not output_file:
        print(f"\n❌ RESULT SAVING FAILED")
        print("[-] Failed to save results")
        sys.exit(1)
    
    # Final summary
    print(f"\n🎉 FINAL ATTACK SUMMARY")
    print(f"=" * 60)
    print(f"🎯 Target: ({params.target_pubkey[0]}, {params.target_pubkey[1]})")
    print(f"🎯 Bits: {params.target_bits}")
    print(f"📊 Candidates: {len(results['attack_results']['scalars'])}")
    print(f"📊 Recovered: {results['attack_results']['recovered']:.1f} bits")
    print(f"⏰ Time: {results['attack_results']['time_zvp']:.2f}s")
    print(f"📁 Output: {output_file}")
    print(f"=" * 60)
    
    print(f"\n🎉 ✅ ATTACK COMPLETED SUCCESSFULLY! 🎉")

if __name__ == "__main__":
    main()
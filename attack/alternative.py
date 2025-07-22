#!/usr/bin/env python3
"""
ZVP-GLV Attack on Window Interleaving (Alternative)
Implementation based on Section 4.5 of "Decompose and conquer: ZVP attacks on GLV curves"

This implements the alternative version of the interleaving algorithm where
d(i)0 * P + d(i)1 * λP is computed in each iteration, using small window values
d(i)0, d(i)1 ∈ {±1, ±3, ..., ±(2^w-1)}.

The attack uses an extended side-channel oracle O*(P) that returns a vector
indicating in which iterations a zero appeared, and employs BSGS for final
key recovery.
"""

import argparse
import json
import time
import os
import sys
from datetime import datetime
from itertools import product
from copy import deepcopy
from collections import defaultdict

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from sage.all import ZZ, RR, log, ceil, floor
except ImportError:
    # Fallback for environments without SageMath
    print("Warning: SageMath not available, using fallback implementation")
    ZZ = int
    RR = float
    log = lambda x: __import__('math').log(x)
    ceil = lambda x: int(__import__('math').ceil(x))
    floor = lambda x: int(__import__('math').floor(x))

# Import attack modules
import dcp
import msm
import utils
import glv as glv_module
from utils import ZVPparams


class WindowInterleavingParams:
    """Parameters for the alternative window interleaving ZVP-GLV attack"""
    
    def __init__(self, target_pubkey, window_size=4, target_bits=None, 
                 iv_polynomials=None, curve_params=None, verbose=False):
        self.target_pubkey = target_pubkey
        self.window_size = window_size  # w parameter
        self.target_bits = target_bits or (window_size * 8)  # Default estimation
        self.iv_polynomials = iv_polynomials or self._get_default_polynomials()
        self.curve_params = curve_params or self._get_secp256k1_params()
        self.verbose = verbose
        
        # Derived parameters
        self.window_values = self._generate_window_values()
        self.total_iterations = ceil(self.target_bits / self.window_size)
        
    def _generate_window_values(self):
        """Generate all possible window values {±1, ±3, ..., ±(2^w-1)}"""
        max_val = 2**(self.window_size - 1)
        odd_values = [2*i - 1 for i in range(1, max_val + 1)]
        return [-v for v in odd_values] + odd_values
    
    def _get_default_polynomials(self):
        """Get default IV polynomials for secp256k1"""
        # TODO: Load from EFD database or predefined set
        return ["f1", "f2", "f3"]  # Placeholder
    
    def _get_secp256k1_params(self):
        """Get secp256k1 curve parameters"""
        return {
            'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            'order': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            'lambda': 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72,
            'gx': 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            'gy': 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        }


class WindowInterleavingGuess:
    """
    Represents a candidate for window interleaving bits d(i)0, d(i)1
    
    This class stores the bit patterns for each iteration and provides
    methods for manipulation and conversion to scalar values.
    """
    
    def __init__(self, window_size, d0_bits=None, d1_bits=None):
        self.window_size = window_size
        self.d0_bits = d0_bits if d0_bits is not None else []
        self.d1_bits = d1_bits if d1_bits is not None else []
    
    def add_iteration(self, d0_val, d1_val):
        """Add bits for a new iteration (prepend for MSB-first)"""
        self.d0_bits.insert(0, ZZ(d0_val))
        self.d1_bits.insert(0, ZZ(d1_val))
    
    def get_scalars(self):
        """Convert bit patterns to scalar values d0, d1"""
        d0 = msm.from_regular_wnaf(self.d0_bits, self.window_size)
        d1 = msm.from_regular_wnaf(self.d1_bits, self.window_size)
        return d0, d1
    
    def size(self):
        """Get number of iterations stored"""
        return len(self.d0_bits)
    
    def is_complete(self, target_iterations):
        """Check if we have bits for all target iterations"""
        return self.size() >= target_iterations
    
    def __repr__(self):
        return f"WindowGuess(d0={self.d0_bits}, d1={self.d1_bits})"
    
    def __eq__(self, other):
        return (self.d0_bits == other.d0_bits and 
                self.d1_bits == other.d1_bits)


class AlternativeZVPAttack:
    """
    Main class implementing the ZVP-GLV attack on window interleaving (alternative)
    
    This attack targets the alternative version of interleaving where each iteration
    computes d(i)0 * P + d(i)1 * λP with small window values.
    """
    
    def __init__(self, params):
        self.params = params
        self.precomputed_points = {}  # P -> set of (g0, g1) that cause zero
        self.point_mappings = {}      # (g0, g1) -> P (if solution exists)
        self.attack_results = {
            'candidates': [],
            'reduced_space_bits': 0,
            'time_precompute': 0,
            'time_attack': 0,
            'time_bsgs': 0
        }
    
    def precompute_dcp_solutions(self):
        """
        Precompute solutions to DCP f(g0, g1*λ) for all window value combinations
        
        This corresponds to the precomputation phase mentioned in section 4.5:
        "At the beginning of the attack, we try to solve DCP f(g0, g1*λ) for every 
        possible combination g0, g1 ∈ {±1, ±3, ..., ±(2^w-1)}"
        """
        start_time = time.time()
        
        if self.params.verbose:
            print(f"[+] Precomputing DCP solutions for window size {self.params.window_size}")
            print(f"    Window values: {self.params.window_values}")
            print(f"    Total combinations: {len(self.params.window_values)**2}")
        
        solutions_found = 0
        
        for g0, g1 in product(self.params.window_values, repeat=2):
            if self.params.verbose and (solutions_found % 100 == 0):
                print(f"    Processing combination ({g0}, {g1})...")
            
            try:
                # Try to solve DCP f(g0, g1*λ)
                # TODO: Integrate with dcp.py module
                solution_point = self._solve_dcp_small_scalars(g0, g1)
                
                if solution_point is not None:
                    # Store the mapping
                    self.point_mappings[(g0, g1)] = solution_point
                    
                    # Initialize or update the reverse mapping
                    if solution_point not in self.precomputed_points:
                        self.precomputed_points[solution_point] = set()
                    self.precomputed_points[solution_point].add((g0, g1))
                    
                    solutions_found += 1
                    
            except Exception as e:
                if self.params.verbose:
                    print(f"    Warning: DCP solution failed for ({g0}, {g1}): {e}")
                continue
        
        self.attack_results['time_precompute'] = time.time() - start_time
        
        if self.params.verbose:
            print(f"[+] Precomputation complete:")
            print(f"    Solutions found: {solutions_found}")
            print(f"    Unique points: {len(self.precomputed_points)}")
            print(f"    Time: {self.attack_results['time_precompute']:.2f}s")
    
    def _solve_dcp_small_scalars(self, g0, g1):
        """
        Solve DCP f(g0, g1*λ) for small scalars
        
        Since both g0 and g1*λ are small, this should be an "easy" DCP instance
        as mentioned in the paper.
        """
        try:
            # Create ZVP parameters for DCP solving
            zvp_params = self._get_zvp_params()
            
            # For alternative interleaving, we solve DCP for (g0, g1*λ)
            # This corresponds to the multiscalar multiplication d(i)0*P + d(i)1*λP
            glv_scalar = (ZZ(g0), ZZ(g1))
            
            # Use the GLV DCP solver from the existing codebase
            solution_point = dcp.solve_glv_dcp_pari(glv_scalar, zvp_params.glv, zvp_params.registers)
            
            if solution_point is not None:
                # Convert to tuple format for easier handling
                return (int(solution_point[0]), int(solution_point[1]))
            
            return None
            
        except Exception as e:
            if self.params.verbose:
                print(f"    DCP solving failed for ({g0}, {g1}): {e}")
            return None
    
    def _get_zvp_params(self):
        """Get ZVP parameters for DCP solving"""
        if not hasattr(self, '_zvp_params_cache'):
            # Initialize GLV parameters
            glv_params = glv_module.GLV.secp256k1()
            
            # Initialize registers with secp256k1 polynomials
            registers = utils.Registers()
            
            # Load default polynomials for secp256k1
            secp256k1_polys = utils.get_secp256k1_polynomials()
            for poly_x, poly_y in secp256k1_polys:
                registers.add_tuple(poly_x, poly_y)
            
            # Create ZVP parameters
            self._zvp_params_cache = utils.ZVPparams(glv_params, registers)
            
        return self._zvp_params_cache
    
    def extended_oracle(self, point, iterations):
        """
        Extended side-channel oracle O*(P) that returns a vector of zeros/ones
        
        This simulates the extended side-channel oracle O*(P) from section 4.5
        that indicates in which iterations a zero intermediate value appeared.
        
        Args:
            point: The point P to query (x, y coordinates)
            iterations: Number of iterations to simulate
            
        Returns:
            List of 0s and 1s indicating zero detection in each iteration
        """
        try:
            # Convert tuple coordinates to curve point
            zvp_params = self._get_zvp_params()
            curve = zvp_params.glv.curve
            
            if point is None:
                return [0] * iterations
            
            P = curve(point[0], point[1])
            
            oracle_vector = []
            
            # Simulate window interleaving algorithm
            for iteration in range(iterations):
                # For each iteration, we need to check if any of the possible
                # (g0, g1) combinations would cause a zero when computed as g0*P + g1*λP
                
                # Get the lambda endomorphism point
                lambda_P = zvp_params.glv.lam * P
                
                # Check all possible window value combinations for this iteration
                zero_detected = False
                
                for g0, g1 in product(self.params.window_values, repeat=2):
                    try:
                        # Compute g0*P + g1*λP
                        intermediate_point = g0 * P + g1 * lambda_P
                        
                        # Check if this causes a zero in any register polynomial
                        if zvp_params.registers.is_zero(P, intermediate_point):
                            zero_detected = True
                            break
                            
                    except Exception:
                        # If computation fails, assume no zero
                        continue
                
                oracle_vector.append(1 if zero_detected else 0)
            
            return oracle_vector
            
        except Exception as e:
            if self.params.verbose:
                print(f"    Oracle simulation failed for point {point}: {e}")
            # Return no zeros detected as fallback
            return [0] * iterations
    
    def run_attack(self):
        """
        Execute the main ZVP-GLV attack algorithm
        
        This implements Algorithm 6 from the paper.
        """
        start_time = time.time()
        
        if self.params.verbose:
            print(f"[+] Starting ZVP-GLV alternative attack")
            print(f"    Target iterations: {self.params.total_iterations}")
        
        # Initialize candidate sets for each iteration
        iteration_candidates = []
        
        for iteration in range(self.params.total_iterations):
            if self.params.verbose:
                print(f"[+] Processing iteration {iteration}")
            
            # Initialize with all possible window value combinations
            candidates = set(product(self.params.window_values, repeat=2))
            
            # Query oracle for each precomputed point
            for point, possible_pairs in self.precomputed_points.items():
                oracle_result = self.extended_oracle(point, self.params.total_iterations)
                
                if oracle_result[iteration] == 1:
                    # Zero detected - candidates must be in possible_pairs
                    candidates = candidates.intersection(possible_pairs)
                else:
                    # No zero detected - candidates must NOT be in possible_pairs
                    candidates = candidates.difference(possible_pairs)
            
            iteration_candidates.append(candidates)
            
            if self.params.verbose:
                print(f"    Iteration {iteration}: {len(candidates)} candidates remaining")
        
        self.attack_results['time_attack'] = time.time() - start_time
        self.attack_results['candidates'] = iteration_candidates
        
        # Calculate reduced space size
        total_combinations = 1
        for candidates in iteration_candidates:
            total_combinations *= len(candidates) if candidates else 1
        
        self.attack_results['reduced_space_bits'] = floor(log(total_combinations, 2)) if total_combinations > 0 else 0
        
        if self.params.verbose:
            print(f"[+] Attack phase complete:")
            print(f"    Reduced space: {self.attack_results['reduced_space_bits']} bits")
            print(f"    Time: {self.attack_results['time_attack']:.2f}s")
        
        return iteration_candidates
    
    def baby_step_giant_step(self, iteration_candidates):
        """
        Apply baby-step giant-step to recover the full private key
        
        This implements the BSGS approach described in section 4.5:
        "cut d0, d1 in halves into upper and lower digits"
        """
        start_time = time.time()
        
        if self.params.verbose:
            print(f"[+] Starting baby-step giant-step phase")
            print(f"    Reduced space: {self.attack_results['reduced_space_bits']} bits")
        
        recovered_key = None
        
        # Try direct enumeration for small spaces
        if self.attack_results['reduced_space_bits'] < 40:
            if self.params.verbose:
                print(f"    Reduced space small enough for direct enumeration")
            
            recovered_key = self._direct_enumeration(iteration_candidates)
            
        elif self.attack_results['reduced_space_bits'] < 80:
            if self.params.verbose:
                print(f"    Using BSGS for moderate space")
            
            recovered_key = self._run_bsgs(iteration_candidates)
        else:
            if self.params.verbose:
                print(f"    Space too large for practical recovery")
                print(f"    This demonstrates the attack reduced the keyspace significantly")
            
            # Still record the reduction as a success
            recovered_key = None
        
        self.attack_results['time_bsgs'] = time.time() - start_time
        self.attack_results['recovered_key'] = recovered_key
        
        if self.params.verbose:
            print(f"[+] BSGS phase complete:")
            print(f"    Recovered key: {hex(recovered_key) if recovered_key else 'Not recovered'}")
            print(f"    Time: {self.attack_results['time_bsgs']:.2f}s")
        
        return recovered_key
    
    def _direct_enumeration(self, iteration_candidates):
        """
        Direct enumeration through the reduced candidate space
        """
        if self.params.verbose:
            print(f"    Enumerating through {len(iteration_candidates)} iterations...")
        
        # Count total combinations
        total_combinations = 1
        for candidates in iteration_candidates:
            total_combinations *= len(candidates) if candidates else 1
        
        if total_combinations > 2**32:  # Too many even for enumeration
            if self.params.verbose:
                print(f"    Even direct enumeration space too large: {total_combinations}")
            return None
        
        # Enumerate through all combinations
        count = 0
        for combination in self._generate_combinations(iteration_candidates):
            count += 1
            if count % 10000 == 0 and self.params.verbose:
                print(f"      Tested {count} combinations...")
            
            # Convert combination to potential private key
            d0_bits, d1_bits = zip(*combination) if combination else ([], [])
            
            try:
                # Reconstruct scalars from window values
                d0 = self._window_values_to_scalar(d0_bits)
                d1 = self._window_values_to_scalar(d1_bits)
                
                # Apply GLV formula: k = d0 + d1 * λ
                lambda_val = self.params.curve_params['lambda']
                order = self.params.curve_params['order']
                potential_key = (d0 + d1 * lambda_val) % order
                
                # Test if this key produces the target public key
                if self._verify_private_key(potential_key):
                    if self.params.verbose:
                        print(f"    ✓ Found private key: {hex(potential_key)}")
                    return potential_key
                    
            except Exception as e:
                if self.params.verbose:
                    print(f"    Error testing combination: {e}")
                continue
        
        if self.params.verbose:
            print(f"    Enumeration complete: tested {count} combinations, no key found")
        return None
    
    def _run_bsgs(self, iteration_candidates):
        """
        Run Baby-Step Giant-Step using the compiled PARI solver
        """
        try:
            import subprocess
            import tempfile
            
            if self.params.verbose:
                print(f"    Setting up BSGS solver...")
            
            # Extract the reduced bounds for d0 and d1
            d0_bounds, d1_bounds = self._calculate_bsgs_bounds(iteration_candidates)
            
            if d0_bounds is None or d1_bounds is None:
                if self.params.verbose:
                    print(f"    Could not determine BSGS bounds")
                return None
            
            # Set up curve parameters
            p = self.params.curve_params['p']
            a = 0  # secp256k1 a parameter
            b = 7  # secp256k1 b parameter
            gx = self.params.curve_params['gx'] 
            gy = self.params.curve_params['gy']
            
            # Target public key (assuming we have target point Q = k*P)
            target_x, target_y = self._parse_target_pubkey()
            
            lambda_val = self.params.curve_params['lambda']
            
            # Create temporary file for result
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                result_file = f.name
            
            # Build command for BSGS solver
            bsgs_cmd = [
                './attack/pari_tools/bsgs_solver',
                str(p), str(a), str(b),
                str(gx), str(gy),  # Generator point P
                str(target_x), str(target_y),  # Target point Q = k*P
                str(lambda_val),
                str(d0_bounds[1]),  # l1 (bits for d0)
                str(d1_bounds[1]),  # l2 (bits for d1)
                result_file
            ]
            
            if self.params.verbose:
                print(f"    Running BSGS solver...")
                print(f"    Command: {' '.join(bsgs_cmd[:8])}... (truncated)")
            
            # Run BSGS solver
            result = subprocess.run(bsgs_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Read result from file
                with open(result_file, 'r') as f:
                    lines = f.read().strip().split('\n')
                    if len(lines) >= 2:
                        d0 = int(lines[0])
                        d1 = int(lines[1])
                        
                        # Reconstruct private key
                        order = self.params.curve_params['order']
                        private_key = (d0 + d1 * lambda_val) % order
                        
                        if self.params.verbose:
                            print(f"    BSGS found: d0={d0}, d1={d1}")
                            print(f"    Private key: {hex(private_key)}")
                        
                        # Clean up
                        os.unlink(result_file)
                        return private_key
            
            if self.params.verbose:
                print(f"    BSGS solver failed: {result.stderr}")
            
            # Clean up
            try:
                os.unlink(result_file)
            except:
                pass
            
            return None
            
        except Exception as e:
            if self.params.verbose:
                print(f"    BSGS execution failed: {e}")
            return None
    
    def _generate_combinations(self, iteration_candidates):
        """Generator for all candidate combinations"""
        if not iteration_candidates:
            return
        
        def _recursive_generate(remaining_iterations, current_combination):
            if not remaining_iterations:
                yield current_combination
                return
            
            current_candidates = remaining_iterations[0]
            rest = remaining_iterations[1:]
            
            for candidate in current_candidates:
                yield from _recursive_generate(rest, current_combination + [candidate])
        
        yield from _recursive_generate(iteration_candidates, [])
    
    def _window_values_to_scalar(self, window_values):
        """Convert window values to scalar using regular w-NAF"""
        if not window_values:
            return 0
        
        # Use MSM module for proper w-NAF conversion
        return msm.from_regular_wnaf(list(window_values), self.params.window_size)
    
    def _verify_private_key(self, private_key):
        """Verify if private key produces target public key"""
        # TODO: Implement public key verification
        # This should compute private_key * G and compare with target public key
        return False  # Placeholder
    
    def _calculate_bsgs_bounds(self, iteration_candidates):
        """Calculate bounds for d0 and d1 for BSGS"""
        # TODO: Analyze iteration candidates to determine realistic bounds
        # For now, use default bounds based on window size
        max_bits_per_component = self.params.window_size * len(iteration_candidates)
        return (0, max_bits_per_component), (0, max_bits_per_component)
    
    def _parse_target_pubkey(self):
        """Parse target public key coordinates"""
        pubkey_hex = self.params.target_pubkey
        if len(pubkey_hex) == 128:
            x_hex = pubkey_hex[:64]
            y_hex = pubkey_hex[64:]
            return int(x_hex, 16), int(y_hex, 16)
        else:
            raise ValueError(f"Invalid public key format: {len(pubkey_hex)} chars")
    
    def save_results(self, output_file):
        """Save attack results in JSON format compatible with existing verification"""
        
        # Calculate total recovered bits (256 - reduced_space_bits)
        total_bits = 256  # secp256k1 key size
        recovered_bits = max(0, total_bits - self.attack_results['reduced_space_bits'])
        
        # Format results in expected JSON structure
        results = {
            'attack_info': {
                'name': 'ZVP-GLV Attack on Window Interleaving (Alternative)',
                'target_curve': 'secp256k1',
                'attack_type': 'Window Interleaving Alternative',
                'timestamp': datetime.now().isoformat(),
                'pubkey': self.params.target_pubkey,
                'window_size': self.params.window_size,
                'target_bits': self.params.target_bits,
                'total_iterations': self.params.total_iterations
            },
            'attack_results': {
                'iteration_candidates': [list(candidates) for candidates in self.attack_results['candidates']],
                'reduced_space_bits': self.attack_results['reduced_space_bits'],
                'recovered_bits': recovered_bits,
                'recovered_key': self.attack_results.get('recovered_key'),
                'time_precompute': self.attack_results['time_precompute'],
                'time_attack': self.attack_results['time_attack'],
                'time_bsgs': self.attack_results['time_bsgs'],
                'time_total': sum([
                    self.attack_results['time_precompute'],
                    self.attack_results['time_attack'], 
                    self.attack_results['time_bsgs']
                ])
            }
        }
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        if self.params.verbose:
            print(f"[+] Results saved to: {output_file}")
            print(f"    File size: {os.path.getsize(output_file)} bytes")


def parse_hex_pubkey(pubkey_hex):
    """Parse hex public key string and validate format"""
    try:
        if pubkey_hex.startswith('0x'):
            pubkey_hex = pubkey_hex[2:]
        
        if pubkey_hex.startswith('04'):
            pubkey_hex = pubkey_hex[2:]
        
        if len(pubkey_hex) != 128:
            raise ValueError(f"Public key must be 128 hex characters, got {len(pubkey_hex)}")
        
        # Validate hex format
        int(pubkey_hex, 16)
        
        return pubkey_hex
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid public key format: {e}")


def main():
    """Main function for the alternative ZVP-GLV attack"""
    
    parser = argparse.ArgumentParser(
        description='ZVP-GLV Attack on Window Interleaving (Alternative)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python alternative.py --pubkey 04ceb6cbbcdbdf5e... --window-size 4
  python alternative.py --pubkey ceb6cbbcdbdf5e... --window-size 3 --bits 128 --verbose
  python alternative.py --pubkey 04abc123... --save results/alternative_w4.json
        """
    )
    
    parser.add_argument('--pubkey', type=parse_hex_pubkey, required=True,
                       help='Target public key in hex format (128 chars)')
    parser.add_argument('--window-size', '-w', type=int, default=4,
                       choices=[3, 4, 5], help='Window size for interleaving (default: 4)')
    parser.add_argument('--bits', type=int, 
                       help='Target number of bits to recover (default: window_size * 8)')
    parser.add_argument('--save', type=str, default='results/alternative_attack.json',
                       help='Output file for results (default: results/alternative_attack.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    print("=" * 70)
    print("ZVP-GLV Attack on Window Interleaving (Alternative)")
    print("Implementation of Section 4.5 from 'Decompose and conquer: ZVP attacks on GLV curves'")
    print("=" * 70)
    
    try:
        # Initialize parameters
        params = WindowInterleavingParams(
            target_pubkey=args.pubkey,
            window_size=args.window_size,
            target_bits=args.bits,
            verbose=args.verbose
        )
        
        if args.verbose:
            print(f"[+] Attack parameters:")
            print(f"    Target public key: {args.pubkey}")
            print(f"    Window size: {args.window_size}")
            print(f"    Target bits: {params.target_bits}")
            print(f"    Total iterations: {params.total_iterations}")
            print(f"    Window values: {len(params.window_values)} values")
        
        # Initialize and run attack
        attack = AlternativeZVPAttack(params)
        
        # Phase 1: Precompute DCP solutions
        attack.precompute_dcp_solutions()
        
        # Phase 2: Run main attack
        iteration_candidates = attack.run_attack()
        
        # Phase 3: Baby-step giant-step
        recovered_key = attack.baby_step_giant_step(iteration_candidates)
        
        # Save results
        attack.save_results(args.save)
        
        # Summary
        print(f"\n[+] Attack Summary:")
        print(f"    Reduced space: {attack.attack_results['reduced_space_bits']} bits")
        print(f"    Recovery rate: {(256 - attack.attack_results['reduced_space_bits']) / 256 * 100:.1f}%")
        print(f"    Recovered key: {hex(recovered_key) if recovered_key else 'Not recovered'}")
        print(f"    Total time: {sum([attack.attack_results['time_precompute'], attack.attack_results['time_attack'], attack.attack_results['time_bsgs']]):.2f}s")
        print(f"    Output file: {args.save}")
        
        return 0 if recovered_key else 1
        
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
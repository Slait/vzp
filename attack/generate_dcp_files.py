#!/usr/bin/env python3
"""
Script to generate precomputed DCP files for ZVP-GLV attacks.

This script generates the interleaving_secp256k1_remapped_*.json files
that are used by alternative.py for fast precomputation.

Usage:
    sage -python generate_dcp_files.py --window-size 3
    sage -python generate_dcp_files.py --window-size 4
    sage -python generate_dcp_files.py --window-size 5
    
Or generate all:
    sage -python generate_dcp_files.py --all
"""

import argparse
import sys
import os
import json
import time
from itertools import product

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from sage.all import ZZ, ceil, log
    import dcp
    import msm
    import utils
    SAGE_AVAILABLE = True
except ImportError:
    print("Error: SageMath is required for DCP file generation")
    print("Please run with: sage -python generate_dcp_files.py")
    sys.exit(1)

def generate_window_values(window_size):
    """Generate all possible window values for given window size"""
    max_val = 2**(window_size - 1)
    odd_values = [2*i - 1 for i in range(1, max_val + 1)]
    return [-v for v in odd_values] + odd_values

def run_dcp_experiments_for_window_size(window_size, verbose=False):
    """
    Run DCP experiments for a specific window size.
    
    This implements the same logic as dcp_all_secp256k1_interleaving_experiments()
    from experiments.py
    """
    if verbose:
        print(f"[+] Generating DCP solutions for window size {window_size}")
        print(f"    This may take several minutes...")
    
    # Create ZVP parameters
    glv_curve = utils.GLVCurve()
    glv_curve.set_secp256k1()
    
    registers = utils.Registers()
    
    # Load secp256k1 polynomials
    try:
        secp256k1_polys = utils.get_secp256k1_polynomials()
        for poly_x, poly_y in secp256k1_polys:
            registers.add_tuple(poly_x, poly_y)
    except:
        # Fallback polynomial
        registers.add_tuple("X1 + X2", "X1 + X2")
        if verbose:
            print(f"    Using fallback polynomial")
    
    # Create ZVP parameters
    zvp_params = utils.ZVPparams(glv_curve, registers)
    zvp_params.target_bits = window_size
    zvp_params.attack = dcp.interleaving_dcp_experiment
    zvp_params.secrets = utils.GLVSecrets(glv_curve)
    
    # Generate window values
    window_values = generate_window_values(window_size)
    
    if verbose:
        print(f"    Window values: {window_values}")
        print(f"    Running {len(window_values)**2} DCP experiments...")
    
    # Run experiments
    all_points = set()
    experiment_count = 0
    successful_experiments = 0
    
    for w0 in window_values:
        for w1 in window_values:
            try:
                # Set up secrets for this experiment
                zvp_params.secrets.k0 = w0
                zvp_params.secrets.k1 = w1
                
                # Run the DCP experiment
                result = dcp.interleaving_dcp_experiment(zvp_params)
                experiment_count += 1
                
                # Extract point if found
                if result.get("recovered") and result.get("point"):
                    point_coords = result["point"]
                    if len(point_coords) == 2:
                        point = glv_curve.curve(point_coords[0], point_coords[1])
                        all_points.add(point)
                        successful_experiments += 1
                        
                        if verbose and successful_experiments <= 10:
                            print(f"    Found DCP solution #{successful_experiments}: ({w0}, {w1}) -> point")
                        
            except Exception as e:
                if verbose and experiment_count <= 10:
                    print(f"    Experiment failed for ({w0}, {w1}): {e}")
                continue
    
    if verbose:
        print(f"    Completed {experiment_count} experiments")
        print(f"    Found {len(all_points)} unique DCP solution points")
    
    return all_points, glv_curve, registers

def create_remapped_data(dcp_points, glv_curve, registers, window_size, verbose=False):
    """
    Create remapped data structure from DCP points.
    
    This implements the remapping logic from dcp_points_remapping().
    """
    if verbose:
        print(f"[+] Creating remapped data structure...")
    
    window_values = generate_window_values(window_size)
    point_list = []
    
    for i, point in enumerate(dcp_points):
        if verbose and i % 10 == 0:
            print(f"    Processing point {i+1}/{len(dcp_points)}...")
            
        scalars = []
        # Test all window value combinations for this point
        for w0 in window_values:
            for w1 in window_values:
                try:
                    P = w0 * point
                    Q = w1 * glv_curve.lam * point
                    
                    # Check if this combination causes zero detection
                    if registers.is_zero(P, Q):
                        scalars.append([int(w0), int(w1)])
                        
                except Exception:
                    continue
        
        if scalars:  # Only include points that have associated scalar pairs
            point_coords = [int(point[0]), int(point[1])]
            point_list.append([point_coords, scalars])
    
    # Create the data structure matching the expected format
    register_strings = registers.to_strings()
    remapped_data = [{
        "register": register_strings,
        "points": point_list
    }]
    
    if verbose:
        print(f"    Remapped data created: {len(point_list)} points with scalar mappings")
    
    return remapped_data

def save_dcp_file(remapped_data, window_size, verbose=False):
    """Save the remapped DCP data to file"""
    # Try to save in both locations
    saved = False
    
    for results_dir in ["attack/results", "results"]:
        try:
            os.makedirs(results_dir, exist_ok=True)
            filename = f"{results_dir}/interleaving_secp256k1_remapped_{window_size}.json"
            
            with open(filename, 'w') as f:
                json.dump(remapped_data, f, indent=2)
            
            if verbose:
                print(f"[+] DCP data saved to: {filename}")
                file_size = os.path.getsize(filename)
                print(f"    File size: {file_size/1024:.1f} KB")
            
            saved = True
            break
            
        except Exception as e:
            if verbose:
                print(f"    Could not save to {results_dir}: {e}")
            continue
    
    if not saved:
        print(f"Error: Could not save DCP file for window size {window_size}")
        return False
    
    return True

def generate_dcp_file_for_window_size(window_size, verbose=False):
    """Generate a complete DCP file for a given window size"""
    start_time = time.time()
    
    if verbose:
        print(f"=" * 60)
        print(f"Generating DCP file for window size {window_size}")
        print(f"=" * 60)
    
    try:
        # Run DCP experiments
        dcp_points, glv_curve, registers = run_dcp_experiments_for_window_size(window_size, verbose)
        
        if not dcp_points:
            print(f"Error: No DCP points found for window size {window_size}")
            return False
        
        # Create remapped data
        remapped_data = create_remapped_data(dcp_points, glv_curve, registers, window_size, verbose)
        
        # Save to file
        success = save_dcp_file(remapped_data, window_size, verbose)
        
        elapsed_time = time.time() - start_time
        
        if verbose:
            print(f"[+] Generation complete for window size {window_size}")
            print(f"    Total time: {elapsed_time:.1f} seconds")
            print(f"    Status: {'SUCCESS' if success else 'FAILED'}")
        
        return success
        
    except Exception as e:
        print(f"Error generating DCP file for window size {window_size}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Generate precomputed DCP files for ZVP-GLV attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    sage -python generate_dcp_files.py --window-size 3
    sage -python generate_dcp_files.py --window-size 4 --verbose
    sage -python generate_dcp_files.py --all
        """
    )
    
    parser.add_argument('--window-size', '-w', type=int, choices=[3, 4, 5],
                       help='Generate DCP file for specific window size')
    parser.add_argument('--all', action='store_true',
                       help='Generate DCP files for all window sizes (3, 4, 5)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if not args.window_size and not args.all:
        parser.error('Must specify either --window-size or --all')
    
    print("ZVP-GLV DCP File Generator")
    print("=" * 40)
    
    if not SAGE_AVAILABLE:
        print("Error: SageMath is required for DCP file generation")
        return 1
    
    success_count = 0
    total_count = 0
    
    if args.all:
        window_sizes = [3, 4, 5]
    else:
        window_sizes = [args.window_size]
    
    for window_size in window_sizes:
        total_count += 1
        if generate_dcp_file_for_window_size(window_size, args.verbose):
            success_count += 1
        
        if args.verbose and len(window_sizes) > 1:
            print()  # Add spacing between window sizes
    
    print(f"\nGeneration Summary:")
    print(f"  Successful: {success_count}/{total_count}")
    print(f"  Status: {'COMPLETE' if success_count == total_count else 'PARTIAL'}")
    
    return 0 if success_count == total_count else 1

if __name__ == "__main__":
    sys.exit(main())
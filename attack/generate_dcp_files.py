#!/usr/bin/env python3
"""
Script to generate precomputed DCP files for ZVP-GLV attacks.

This script generates the interleaving_secp256k1_remapped_*.json files
that are used by alternative.py for fast precomputation.

This script follows the exact methodology from the original project:
1. Run DCP experiments using dcp_all_secp256k1_interleaving_experiments()
2. Use dcp_points_remapping() to create the remapped files

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
    import zvp_glv_inter_easy_prec as inter_easy
    import experiments
    SAGE_AVAILABLE = True
except ImportError:
    print("Error: SageMath is required for DCP file generation")
    print("Please run with: sage -python generate_dcp_files.py")
    sys.exit(1)

def setup_zvp_params_for_experiments(window_size, verbose=False):
    """
    Set up ZVP parameters for DCP experiments following the original project methodology.
    
    This creates the same setup as used in experiments.py
    """
    if verbose:
        print(f"[+] Setting up ZVP parameters for window size {window_size}")
    
    # Create ZVP parameters - use 256 bits for secp256k1
    zvp_params = utils.ZVPparams(bits=256)
    
    # Set up GLV curve for secp256k1
    zvp_params.generate_secp256k1_secrets()  # This sets up the GLV curve and secrets
    
    # Set up registers with secp256k1 polynomials
    try:
        secp256k1_polys = utils.get_secp256k1_polynomials()
        for poly_x, poly_y in secp256k1_polys:
            zvp_params.registers.add_tuple(poly_x, poly_y)
        if verbose:
            print(f"    Loaded {len(secp256k1_polys)} secp256k1 polynomials")
    except Exception as e:
        # Fallback polynomial (same as in tests.py)
        X1, Y1, X2, Y2 = zvp_params.registers.gens
        zvp_params.registers.add_tuple(X1 + X2 + 2, X1 + X2 + 2)
        if verbose:
            print(f"    Using fallback polynomial: X1 + X2 + 2")
    
    # Set target bits and attack function
    zvp_params.target_bits = window_size
    zvp_params.attack = dcp.interleaving_dcp_experiment
    
    if verbose:
        print(f"    ZVP parameters configured:")
        print(f"    - Bits: {zvp_params.bits}")
        print(f"    - Target bits: {zvp_params.target_bits}")
        print(f"    - Registers: {len(zvp_params.registers.polynomials)} polynomials")
    
    return zvp_params

def run_dcp_experiments_for_window_size(window_size, verbose=False):
    """
    Run DCP experiments using the exact methodology from experiments.py
    
    This calls dcp_all_secp256k1_interleaving_experiments() to generate
    the experiment results that will be used by dcp_points_remapping().
    """
    if verbose:
        print(f"[+] Running DCP experiments for window size {window_size}")
        print(f"    This uses the same logic as experiments.py")
    
    # Set up ZVP parameters
    zvp_params = setup_zvp_params_for_experiments(window_size, verbose)
    
    # Run the experiments using the original function from experiments.py
    if verbose:
        print(f"    Calling dcp_all_secp256k1_interleaving_experiments()...")
        start_time = time.time()
    
    # This will create result files in the results/ directory
    experiments.dcp_all_secp256k1_interleaving_experiments(zvp_params, window_size)
    
    if verbose:
        elapsed_time = time.time() - start_time
        print(f"    DCP experiments completed in {elapsed_time:.1f}s")
        print(f"    Results saved to: results/{zvp_params.filename}_{window_size}_*.json")
    
    return zvp_params

def create_remapped_data_using_original_function(zvp_params, window_size, verbose=False):
    """
    Create remapped data using the original dcp_points_remapping() function.
    
    This is the exact function from zvp_glv_inter_easy_prec.py
    """
    if verbose:
        print(f"[+] Creating remapped data using dcp_points_remapping()")
        print(f"    This will process experiment results and create mappings")
    
    # Call the original remapping function
    # This will load results from files and create the remapped JSON
    inter_easy.dcp_points_remapping(zvp_params, window_size)
    
    if verbose:
        print(f"    Remapped data created and saved to: results/interleaving_secp256k1_remapped_{window_size}.json")
    
    return True

def verify_generated_file(window_size, verbose=False):
    """Verify that the generated file exists and is valid"""
    filename = f"results/interleaving_secp256k1_remapped_{window_size}.json"
    
    if not os.path.exists(filename):
        if verbose:
            print(f"    Warning: Expected file not found: {filename}")
        return False
    
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        if verbose:
            file_size = os.path.getsize(filename)
            print(f"    Generated file verified: {filename}")
            print(f"    File size: {file_size/1024:.1f} KB")
            
            # Count points and mappings
            total_points = 0
            total_mappings = 0
            for register_data in data:
                points = register_data.get("points", [])
                total_points += len(points)
                for point_data in points:
                    if len(point_data) > 1:
                        total_mappings += len(point_data[1])
            
            print(f"    Content: {len(data)} register sets, {total_points} points, {total_mappings} scalar mappings")
        
        return True
        
    except Exception as e:
        if verbose:
            print(f"    Error reading generated file: {e}")
        return False

def generate_dcp_file_for_window_size(window_size, verbose=False):
    """Generate a complete DCP file for a given window size using original methodology"""
    start_time = time.time()
    
    if verbose:
        print(f"=" * 60)
        print(f"Generating DCP file for window size {window_size}")
        print(f"=" * 60)
    
    try:
        # Ensure results directory exists
        os.makedirs("results", exist_ok=True)
        
        # Step 1: Run DCP experiments (creates intermediate result files)
        zvp_params = run_dcp_experiments_for_window_size(window_size, verbose)
        
        # Step 2: Create remapped data using original function
        create_remapped_data_using_original_function(zvp_params, window_size, verbose)
        
        # Step 3: Verify the generated file
        success = verify_generated_file(window_size, verbose)
        
        elapsed_time = time.time() - start_time
        
        if verbose:
            print(f"[+] Generation complete for window size {window_size}")
            print(f"    Total time: {elapsed_time:.1f} seconds")
            print(f"    Status: {'SUCCESS' if success else 'FAILED'}")
        
        return success
        
    except Exception as e:
        print(f"Error generating DCP file for window size {window_size}: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Generate precomputed DCP files for ZVP-GLV attacks using original project methodology',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script follows the exact methodology from the original project:
1. Calls experiments.dcp_all_secp256k1_interleaving_experiments()
2. Calls zvp_glv_inter_easy_prec.dcp_points_remapping()
3. Generates interleaving_secp256k1_remapped_*.json files

Examples:
    sage -python generate_dcp_files.py --window-size 3
    sage -python generate_dcp_files.py --window-size 4 --verbose
    sage -python generate_dcp_files.py --all --verbose

Note: This script requires SageMath and may take several minutes per window size.
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
    print("Using Original Project Methodology")
    print("=" * 50)
    
    if not SAGE_AVAILABLE:
        print("Error: SageMath is required for DCP file generation")
        print("Please run with: sage -python generate_dcp_files.py")
        return 1
    
    success_count = 0
    total_count = 0
    total_start_time = time.time()
    
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
    
    total_elapsed_time = time.time() - total_start_time
    
    print(f"\nGeneration Summary:")
    print(f"  Successful: {success_count}/{total_count}")
    print(f"  Total time: {total_elapsed_time:.1f} seconds")
    print(f"  Status: {'COMPLETE' if success_count == total_count else 'PARTIAL'}")
    
    if success_count > 0:
        print(f"\nGenerated files:")
        for window_size in window_sizes:
            filename = f"results/interleaving_secp256k1_remapped_{window_size}.json"
            if os.path.exists(filename):
                file_size = os.path.getsize(filename)
                print(f"  - {filename} ({file_size/1024:.1f} KB)")
    
    return 0 if success_count == total_count else 1

if __name__ == "__main__":
    sys.exit(main())
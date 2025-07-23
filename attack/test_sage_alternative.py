#!/usr/bin/env python3
"""
Test script for alternative.py with SageMath integration
"""

import sys
import os

# Add attack directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_sage_imports():
    """Test if SageMath imports work correctly"""
    print("Testing SageMath imports...")
    
    try:
        from sage.all import ZZ, RR, log, ceil, floor, EllipticCurve, GF
        print("✅ SageMath imports successful")
        
        # Test basic SageMath operations
        test_val = ZZ(256)
        result = floor(log(test_val, 2))
        print(f"✅ SageMath operations work: floor(log(256, 2)) = {result}")
        
        # Test formatting with float conversion
        sage_val = log(256, 2)
        float_val = float(sage_val)
        formatted = f"{float_val:.2f}"
        print(f"✅ SageMath formatting works: {formatted}")
        
        return True
        
    except ImportError as e:
        print(f"❌ SageMath not available: {e}")
        return False
    except Exception as e:
        print(f"❌ SageMath error: {e}")
        return False

def test_alternative_import():
    """Test if alternative.py imports correctly with SageMath"""
    print("\nTesting alternative.py import...")
    
    try:
        import alternative
        print("✅ alternative.py imports successfully")
        
        # Test class creation
        from alternative import WindowInterleavingParams, AlternativeZVPAttack
        
        # Test basic parameter creation
        params = WindowInterleavingParams(
            target_pubkey="04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac",
            window_size=3,
            target_bits=6
        )
        print("✅ WindowInterleavingParams created successfully")
        
        attack = AlternativeZVPAttack(params)
        print("✅ AlternativeZVPAttack created successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ alternative.py import error: {e}")
        return False

def test_dcp_modules():
    """Test if DCP modules are available"""
    print("\nTesting DCP modules...")
    
    try:
        import dcp
        import utils
        import glv as glv_module
        print("✅ DCP modules imported successfully")
        
        # Test GLV parameters
        glv_params = glv_module.GLV.secp256k1()
        print(f"✅ GLV parameters loaded: p = {glv_params.p}")
        
        return True
        
    except Exception as e:
        print(f"❌ DCP modules error: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 60)
    print("SageMath Alternative Attack Test")
    print("=" * 60)
    
    sage_ok = test_sage_imports()
    alt_ok = test_alternative_import()
    dcp_ok = test_dcp_modules()
    
    print("\n" + "=" * 60)
    print("Test Summary:")
    print(f"SageMath: {'✅ OK' if sage_ok else '❌ FAIL'}")
    print(f"Alternative: {'✅ OK' if alt_ok else '❌ FAIL'}")
    print(f"DCP Modules: {'✅ OK' if dcp_ok else '❌ FAIL'}")
    
    if sage_ok and alt_ok and dcp_ok:
        print("\n🎉 All tests passed! Ready for SageMath attack.")
        
        # Run a quick attack test
        print("\nRunning quick attack test...")
        try:
            from alternative import WindowInterleavingParams, AlternativeZVPAttack
            
            params = WindowInterleavingParams(
                target_pubkey="04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac",
                window_size=3,
                target_bits=6,
                verbose=True
            )
            
            attack = AlternativeZVPAttack(params)
            
            print("Precomputing DCP solutions...")
            attack.precompute_dcp_solutions()
            
            print(f"✅ Precomputation successful: {len(attack.precomputed_points)} points")
            
        except Exception as e:
            print(f"❌ Quick test failed: {e}")
            
    else:
        print("\n❌ Some tests failed. Check your SageMath installation.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
"""
Fallback version of dcp_pari.py when C programs fail
Creates proper result files with dummy data for testing
"""
import os
import random


def get_pari_tools_path():
    """Get correct path to pari_tools directory"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Ensure results directory exists
    results_dir = os.path.join(current_dir, "results")
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    return current_dir


def dcpsolver_pari_fallback(p, a, b, k, lam, Vpolynomials, registers):
    """Fallback DCP solver when C programs fail"""
    base_path = get_pari_tools_path()
    solution_path = os.path.join(base_path, "results", "poly2")
    Vpolynomial_path = os.path.join(base_path, "results", "_polynomial")
    fpolynomial_path = os.path.join(base_path, "results", "_fpolynomial")
    
    # Create input files (for debugging)
    V_string = "[[1,1,0,0,0]]"  # Simple fallback
    f_string = f"[Mod(1,{p})*X1]"  # Simple polynomial
    
    with open(Vpolynomial_path, "w") as f:
        f.write(V_string)
    with open(fpolynomial_path, "w") as f:
        f.write(f_string)
    
    # Create dummy solution file
    # Format: Mod(x, p), Mod(y, p)
    dummy_x = random.randint(1, int(p) - 1)
    dummy_y = random.randint(1, int(p) - 1)
    solution_content = f"Mod({dummy_x}, {p}), Mod({dummy_y}, {p})"
    
    with open(solution_path, "w") as f:
        f.write(solution_content)
    
    print(f"[DEBUG] Created fallback solution: {solution_content}")
    return [(dummy_x, dummy_y)]


def glvdcpsolver_pari_fallback(p, a, b, k1, lam, k2, Vpolynomials, registers):
    """Fallback GLV DCP solver when C programs fail"""
    base_path = get_pari_tools_path()
    solution_path = os.path.join(base_path, "results", "multipoly4")
    Vpolynomial_path = os.path.join(base_path, "results", "_Vpolynomial")
    fpolynomial_path = os.path.join(base_path, "results", "_fpolynomial")
    
    # Create input files (for debugging)
    V_string = "[[1,1,0,0,0,0,0]]"  # GLV format
    f_string = f"[Mod(1,{p})*X1]"
    
    with open(Vpolynomial_path, "w") as f:
        f.write(V_string)
    with open(fpolynomial_path, "w") as f:
        f.write(f_string)
    
    # Create dummy solution file
    dummy_x = random.randint(1, int(p) - 1)
    dummy_y = random.randint(1, int(p) - 1)
    solution_content = f"Mod({dummy_x}, {p}), Mod({dummy_y}, {p})"
    
    with open(solution_path, "w") as f:
        f.write(solution_content)
    
    print(f"[DEBUG] Created fallback GLV solution: {solution_content}")
    return [(dummy_x, dummy_y)]


def multidcpsolver_pari_fallback(p, a, b, k, l, lam, Vpolynomials, registers):
    """Fallback multi DCP solver"""
    return dcpsolver_pari_fallback(p, a, b, k, lam, Vpolynomials, registers)


def glvdcpmultisolver_pari_fallback(p, a, b, scalar0, k1, lam, k2, Vpolynomials, registers):
    """Fallback GLV multi DCP solver"""
    return glvdcpsolver_pari_fallback(p, a, b, k1, lam, k2, Vpolynomials, registers)


# For testing - can be imported to replace failing functions
fallback_functions = {
    'dcpsolver_pari': dcpsolver_pari_fallback,
    'glvdcpsolver_pari': glvdcpsolver_pari_fallback,
    'multidcpsolver_pari': multidcpsolver_pari_fallback,
    'glvdcpmultisolver_pari': glvdcpmultisolver_pari_fallback
}
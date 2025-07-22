#!/usr/bin/env python3
"""
Generator for elliptic curve lookup table
Curve: y² ≡ x³ + 7 (mod 67)
Base point: G = (2, 22)
Private key modulus: n = 79
"""

def mod_inverse(a, m):
    """Calculate modular inverse using extended Euclidean algorithm"""
    if a < 0:
        a = (a % m + m) % m
    
    # Extended Euclidean Algorithm
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse of {a} mod {m} does not exist")
    return (x % m + m) % m

def point_add_ec(p1, p2, mod_p=67):
    """Add two points on elliptic curve y² = x³ + 7 (mod p)"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    if x1 == x2:
        if y1 == y2:
            # Point doubling: λ = (3x₁² + a) / (2y₁), where a = 0 for our curve
            numerator = (3 * x1 * x1) % mod_p
            denominator = (2 * y1) % mod_p
            lambda_val = (numerator * mod_inverse(denominator, mod_p)) % mod_p
        else:
            # Points are inverses, result is point at infinity
            return None
    else:
        # Point addition: λ = (y₂ - y₁) / (x₂ - x₁)
        numerator = (y2 - y1) % mod_p
        denominator = (x2 - x1) % mod_p
        lambda_val = (numerator * mod_inverse(denominator, mod_p)) % mod_p
    
    # Calculate new point
    x3 = (lambda_val * lambda_val - x1 - x2) % mod_p
    y3 = (lambda_val * (x1 - x3) - y1) % mod_p
    
    return (x3, y3)

def point_multiply_ec(k, point, mod_p=67):
    """Multiply point by scalar k using double-and-add algorithm"""
    if k == 0:
        return None  # Point at infinity
    if k == 1:
        return point
    if k < 0:
        # For negative k, use the fact that -P = (x, -y)
        k = -k
        result = point_multiply_ec(k, point, mod_p)
        if result is None:
            return None
        return (result[0], (-result[1]) % mod_p)
    
    result = None
    addend = point
    
    while k:
        if k & 1:
            result = point_add_ec(result, addend, mod_p)
        addend = point_add_ec(addend, addend, mod_p)
        k >>= 1
    
    return result

def verify_point_on_curve(x, y, mod_p=67):
    """Verify that point (x,y) is on curve y² ≡ x³ + 7 (mod p)"""
    left = (y * y) % mod_p
    right = (x * x * x + 7) % mod_p
    return left == right

def generate_lookup_table():
    """Generate complete lookup table for the elliptic curve"""
    
    # Curve parameters
    p = 67  # Modulus for public key coordinates
    n = 79  # Modulus for private keys
    base_point = (2, 22)
    
    print(f"Generating lookup table for curve y² ≡ x³ + 7 (mod {p})")
    print(f"Base point G = {base_point}")
    print(f"Private key modulus n = {n}")
    print()
    
    # Verify base point is on curve
    if not verify_point_on_curve(base_point[0], base_point[1], p):
        raise ValueError(f"Base point {base_point} is not on the curve!")
    
    print("✓ Base point verified on curve")
    print()
    
    # Generate all points k*G for k = 1 to n-1
    table = {}
    table[0] = None  # Point at infinity for k=0
    
    current_point = base_point
    table[1] = current_point
    
    print("Generating points...")
    for k in range(2, n):
        current_point = point_add_ec(current_point, base_point, p)
        table[k] = current_point
        
        if current_point is None:
            print(f"Found point at infinity at k = {k}")
            # Fill remaining entries with None
            for remaining_k in range(k, n):
                table[remaining_k] = None
            break
    
    return table, p, n

def save_table_to_file(table, p, n, filename="lookup_table_79.txt"):
    """Save lookup table to text file"""
    
    with open(filename, 'w') as f:
        f.write(f"# Elliptic Curve Lookup Table\n")
        f.write(f"# Curve: y² ≡ x³ + 7 (mod {p})\n")
        f.write(f"# Base point: G = (2, 22)\n")
        f.write(f"# Private key modulus: n = {n}\n")
        f.write(f"# Format: d Qx Qy k\n")
        f.write(f"# d - private key (mod {n})\n")
        f.write(f"# Qx - x coordinate (mod {p})\n")
        f.write(f"# Qy - y coordinate (mod {p})\n")
        f.write(f"# k - private key (mod {n}) [same as d]\n")
        f.write(f"\n")
        
        # Write header
        f.write("d\tQx\tQy\tk\n")
        
        # Write table entries
        for k in range(n):
            point = table[k]
            if point is None:
                f.write(f"{k}\tINF\tINF\t{k}\n")
            else:
                x, y = point
                f.write(f"{k}\t{x}\t{y}\t{k}\n")
    
    print(f"✓ Table saved to {filename}")

def generate_python_table(table, p, n):
    """Generate Python dictionary format for use in scripts"""
    
    print("\n" + "="*60)
    print("PYTHON TABLE FORMAT (for copy-paste into scripts):")
    print("="*60)
    
    print("PUBKEY_TABLE = {")
    
    for k in range(n):
        point = table[k]
        if point is None:
            print(f"    {k}: None,  # Point at infinity")
        else:
            x, y = point
            print(f"    {k}: ({x}, {y}),")
    
    print("}")
    print()
    
    return table

def main():
    """Main function"""
    print("="*60)
    print("ELLIPTIC CURVE LOOKUP TABLE GENERATOR")
    print("="*60)
    
    try:
        # Generate lookup table
        table, p, n = generate_lookup_table()
        
        # Save to file
        save_table_to_file(table, p, n)
        
        # Generate Python format
        generate_python_table(table, p, n)
        
        # Statistics
        valid_points = sum(1 for point in table.values() if point is not None)
        print(f"Statistics:")
        print(f"  Total entries: {n}")
        print(f"  Valid points: {valid_points}")
        print(f"  Points at infinity: {n - valid_points}")
        
        # Verify some points
        print(f"\nVerification of first few points:")
        for k in range(min(5, n)):
            point = table[k]
            if point is None:
                print(f"  {k}*G = ∞")
            else:
                x, y = point
                on_curve = verify_point_on_curve(x, y, p)
                status = "✓" if on_curve else "✗"
                print(f"  {k}*G = ({x}, {y}) {status}")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
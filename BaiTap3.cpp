#include <iostream>  
using namespace std;  

// Hàm tính GCD  
int gcd(int a, int b) {  
    return (b == 0) ? a : gcd(b, a % b);  
}  

// Hàm Euclid mở rộng  
int extended_euclid(int a, int b, int &x, int &y) {  
    if (b == 0) {  
        x = 1;   
        y = 0;  
        return a;  
    }  
    int x1, y1;  
    int gcd = extended_euclid(b, a % b, x1, y1);  
    x = y1;  
    y = x1 - (a / b) * y1;  
    return gcd;  
}  

// Hàm tìm nghịch đảo modulo  
int mod_inverse(int a, int m) {  
    int x, y;  
    int gcd = extended_euclid(a, m, x, y); // Tìm GCD và hệ số x, y  
    
    if (gcd != 1) {  
        return -1; // Không tồn tại nghịch đảo  
    }  
    
    // Đảm bảo x là dương  
    return (x % m + m) % m; // Trả về x trong khoảng [0, m-1]  
}  

int main() {  
    int a, m;  
    cout << "Nhap a, m: ";  
    cin >> a >> m;  
    
    if (gcd(a, m) != 1) {  
        cout << "Khong ton tai nghich dao modulo vi gcd(a, m) != 1.\n";  
        return 0;  
    }  
    
    int inv = mod_inverse(a, m);  
    cout << "Nghich dao cua " << a << " mod " << m << " la: " << inv << endl;  
    cout << "Kiem tra: " << a << " * " << inv << " % " << m << " = " << (1LL * a * inv % m) << endl;  
    
    return 0;  
}  
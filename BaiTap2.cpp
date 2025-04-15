#include <iostream>  
#include <map>  
#include <cmath>  
#include <string>  
using namespace std;  

// Tính Entropy  
double calculate_entropy(const string& text) {  
    map<char, int> freq; // Lưu tần suất các ký tự  
    for (char c : text) freq[c]++; // Đếm tần suất của mỗi ký tự  

    double entropy = 0.0; // Khởi tạo biến entropy  
    for (auto& pair : freq) {  
        double p = (double)pair.second / text.size(); // Tính xác suất ký tự  
        entropy -= p * log2(p); // Cập nhật giá trị entropy  
    }  
    return entropy; // Trả về giá trị entropy  
}  

// Tính độ dư thừa thông tin  
double calculate_redundancy(const string& text) {  
    int N = 256; // Số lượng ký tự có thể có (ASCII)  
    double max_entropy = log2(N); // Entropy tối đa  
    double actual_entropy = calculate_entropy(text); // Entropy thực tế  
    return max_entropy - actual_entropy; // Tính độ dư thừa thông tin  
}  

int main() {  
    string input;  
    cout << "Enter a string of characters: ";  
    getline(cin, input); // Đọc chuỗi từ người dùng  

    double H = calculate_entropy(input); // Tính entropy  
    cout << "Entropy: " << H << endl; // In giá trị entropy  

    double redundancy = calculate_redundancy(input); // Tính độ dư thừa thông tin  
    cout << "Redundancy: " << redundancy << endl; // In giá trị độ dư thừa thông tin  

    return 0;  
}  
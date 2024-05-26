#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "normal_api.h"

void getCurrentTime() {
    time_t now = time(NULL);
    printf("[ahoy] Current time: %s", ctime(&now));
}

void createAndWriteFile() {
    FILE *file = fopen("test.txt", "w");
    if (file != NULL) {
        fputs("[ahoy] This is a test file.\n", file);
        fclose(file);
        printf("[ahoy] File 'test.txt' created and written successfully.\n");
    } else {
        printf("[ahoy] Failed to create file.\n");
    }
}

void allocateAndFreeMemory() {
    int* ptr = (int*)malloc(sizeof(int));
    if (ptr != NULL) {
        *ptr = 42;
        printf("[ahoy] Memory allocated and set to %d.\n", *ptr);
        free(ptr);
        printf("[ahoy] Memory freed.\n");
    } else {
        printf("[ahoy] Failed to allocate memory.\n");
    }
}

void generateRandomNumber() {
    srand(time(NULL)); // Seed the random number generator
    int randomNumber = rand() % 100; // Generate a random number between 0 and 99
    printf("[ahoy] Random number: %d\n", randomNumber);
}

double custom_fabs(double x) {
    if (x < 0) {
        return -x;
    }
    return x;
}

double sqrt(double number) {
    if (number <= 0) {
        return 0; // Return 0 for non-positive numbers to avoid infinite loop
    }

    double squareRoot = number;
    double temp = 0;

    while (custom_fabs(squareRoot - temp) > 1e-10) { // Using a small threshold to stop the loop
        temp = squareRoot;
        squareRoot = (number/temp + temp) / 2;
    }

    return squareRoot;
}



void calculateSquareRoot() {
    double numbers[] = {463634.0, 898897037.0, 12345678.0, 32, -4, 16}; 
    int size = sizeof(numbers) / sizeof(numbers[0]); 

    for (int i = 0; i < size; i++) {
        double squareRoot = sqrt(numbers[i]);
        if (numbers[i] > 0) {
            printf("[ahoy] The square root of %.2f is %.2f.\n", numbers[i], squareRoot);
        } else {
            printf("[ahoy] The square root of %.2f is not a real number.\n", numbers[i]);
        }
    }

}


void executeAPIFunction() {
    srand((unsigned int)time(NULL)); 
    int choice = rand() % 5; 
    
    switch (choice) {
        case 0:
            getCurrentTime();
            break;
        case 1:
            createAndWriteFile();
            break;
        case 2:
            allocateAndFreeMemory();
            break;
        case 3:
            generateRandomNumber();
            break;
        case 4:
            calculateSquareRoot();
            break;
    }
}


// int main() {
//     executeAPIFunction();
//     return 0;
// }

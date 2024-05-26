#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ARRAY_SIZE 30

// Function to compare two numbers for qsort
int compare(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

// Binary Search function
int binarySearch(int arr[], int l, int r, int x) {
    if (r >= l) {
        int mid = l + (r - l) / 2;

        // If the element is present at the middle
        if (arr[mid] == x) return mid;

        // If element is smaller than mid, then it can only be in left subarray
        if (arr[mid] > x) return binarySearch(arr, l, mid - 1, x);

        // Else the element can only be in right subarray
        return binarySearch(arr, mid + 1, r, x);
    }

    // Element is not present in array
    return -1;
}

int main() {
    int arr[ARRAY_SIZE];
    int n = ARRAY_SIZE;
    int result;
    srand(time(NULL));

    // Generate random array
    printf("Original Array:\n");
    for (int i = 0; i < n; i++) {
        arr[i] = rand() % 100; // Random numbers between 0 and 99
        printf("%d ", arr[i]);
    }

    // Sort the array
    qsort(arr, n, sizeof(int), compare);

    // Select a random number to search
    int target = arr[rand() % n];

    // Perform binary search
    result = binarySearch(arr, 0, n - 1, target);

    // Output results
    printf("\n\nSorted Array:\n");
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }

    printf("\n\nNumber to find: %d\n", target);
    printf("Index of %d in sorted array: %d\n", target, result);

    return 0;
}

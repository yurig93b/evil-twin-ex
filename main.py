import os

from terminal import Terminal


# Import the necessary packages

def is_root():
    return os.geteuid() == 0

def main():
    if not is_root():
        print("Please run as root...")
        exit(1)

    Terminal().show()


if __name__ == "__main__":
    main()

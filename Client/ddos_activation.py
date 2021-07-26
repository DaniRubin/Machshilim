import machshilim_client_for_ddos
import time

AMOUNT = 250

def main():
    for i in range(AMOUNT):
        print(f"Interval number {i}")
        machshilim_client_for_ddos.runDDOS()


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))

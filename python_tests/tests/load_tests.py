import multiprocessing
import subprocess
import unittest
import time
import requests

TEST_SERVER = "http://test.openport.io:8000"
# TEST_SERVER = "http://localhost:8001"
TEST_SERVER = "http://test.openport.io:8001"


# TEST_SERVER = "https://test.openport.io"


def do_request(i):
    url = f"{TEST_SERVER}/test/slow?seconds=10"
    try:
        t = time.time()
        print(f"Request {i}")
        if 1 == 1:
            r = requests.get(url, timeout=None)
            print(f"{i} - {r.status_code} - {time.time() - t}")
        else:
            p = subprocess.Popen(
                ["curl", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p.wait()
            p.close()

            print(f"{i} -  - {time.time() - t}")
        # if r.status_code != 200:
        #     print(f"Error: {r.status_code}")
    except Exception as e:
        print(e)


class LoadTests(unittest.TestCase):
    def test_nginx_overload(self):
        nr_of_processes = 100
        with multiprocessing.Pool(processes=nr_of_processes) as pool:
            pool.map(do_request, range(nr_of_processes))


if __name__ == "__main__":
    unittest.main()

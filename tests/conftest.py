def pytest_addoption(parser):
    parser.addoption("--serial", action="store", type=int)
    parser.addoption("--reader", action="store")

def pytest_addoption(parser):
    parser.addoption("--device", action="store", type=int)
    parser.addoption("--reader", action="store")

def pytest_addoption(parser):
    parser.addoption("--device", action="store", type=int)
    parser.addoption("--reader", action="store")
    parser.addoption("--no-serial", action="store_true")

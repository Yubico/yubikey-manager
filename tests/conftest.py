def pytest_addoption(parser):
    parser.addoption("--device", action="store", type=int)
    parser.addoption("--no-serial", action="store_true")

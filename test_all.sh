cd nim_config
nimble run config
cd ..
pytest test_serialization.py -s
cd nim_config
nimble run test_python_config

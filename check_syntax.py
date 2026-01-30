import ast
import sys
try:
    with open('scanners/bacnet_scanner.py', 'r') as f:
        ast.parse(f.read())
    print('Syntax OK')
except SyntaxError as e:
    print(f'Syntax Error: {e}')
    sys.exit(1)

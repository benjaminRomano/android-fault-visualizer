#!/bin/bash

# Format Python files with Black
black .

# Clean Jupyter notebook outputs
find . -name "*.ipynb" -exec jupyter nbconvert --clear-output --inplace {} \;

echo "Formatting complete!"

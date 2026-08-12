pip install angr capstone pydot networkx

sudo apt-get install graphviz

# install tree-sitter
git clone https://github.com/tree-sitter/tree-sitter
cd tree-sitter/cli
npm install
npm run build
sudo ln -s $(pwd)/tree-sitter /usr/local/bin/tree-sitter 
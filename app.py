"""打包/直接运行入口：python app.py 等同 python -m liveurldeduper"""

import sys

from liveurldeduper.cli import main

if __name__ == "__main__":
    sys.exit(main())

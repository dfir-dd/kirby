import coloredlogs

import utils
from utils import HostAnalyzer


def main():
    args = utils.cli.arguments()

    analyzer = HostAnalyzer(args.targets, args.output, overwrite=args.overwrite)
    analyzer.analyze_targets()
    

if __name__ == '__main__':
    coloredlogs.install(level='INFO')
    main()

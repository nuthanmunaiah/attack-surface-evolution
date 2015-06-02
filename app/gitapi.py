import re

import gitapi

RE_FUNC_CHANGED = re.compile('(\w*)(?:\s?\()')


class Repo(gitapi.Repo):
    @classmethod
    def git_clone(cls, url, path, *args):
        gitapi.Repo.command(None, 'clone', url, path, *args)
        return Repo(path)

    def git_patch(self, identifier, file=None):
        cmds = ['log', '-1', '-p', identifier]
        if file:
            cmds += ['--', file]
        return self.git_command(*cmds)

    def git_diff_tree(self, identifier):
        cmds = ['diff-tree', '--name-only', '-r', identifier, '--no-commit-id']
        return self.git_command(*cmds)

    def get_files_changed(self, identifier):
        return [
            line for line in self.git_diff_tree(identifier).split('\n')
            if line.strip('\n')
        ]

    def get_functions_changed(self, identifier, file):
        funcs = set()

        patch = self.git_patch(identifier, file)
        if 'commit %s' % identifier in patch:
            for line in patch.split('\n'):
                if line.startswith('@@'):
                    match = RE_FUNC_CHANGED.search(line)
                    if match:
                        funcs.add(match.group(1))

        return list(funcs)

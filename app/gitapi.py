import gitapi


class Repo(gitapi.Repo):
    def git_patch(self, identifier, file=None, **kwargs):
        cmds = ['log', '-n', '1', '-p', identifier]
        if file: cmds += ['--', file]
        if kwargs:
            for key in kwargs:
                cmds += [key, kwargs[key]]
        return self.git_command(*cmds)

    def git_clean(self):
        cmds = ['clean', '-f', '-d']
        return self.git_command(*cmds)


    def git_reset(self, source):
        cmds = ['reset', source, '--hard']
        return self.git_command(*cmds)


    def git_diff_tree(self, source):
        cmds = ['diff-tree', '--name-only', '-r', source, '--no-commit-id']
        return self.git_command(*cmds)
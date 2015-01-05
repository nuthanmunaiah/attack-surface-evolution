import gitapi


class Repo(gitapi.Repo):
    def git_patch_log(self, identifier, **kwargs):
        cmds = ['log', '-p', identifier, '-n', '1']
        if kwargs:
            for key in kwargs:
                cmds += [key, kwargs[key]]
        return self.git_command(*cmds)


    def git_clean(self, del_untracked=False):
        cmds = ['clean', '-f']
        if del_untracked:
            cmds += ['-d']
        return self.git_command(*cmds)


    def git_reset(self, source):
        cmds = ['reset', source, '--hard']
        return self.git_command(*cmds)
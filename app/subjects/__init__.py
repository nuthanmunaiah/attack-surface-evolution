from app.errors import UnknownSubjectError
from app.subjects import curl, ffmpeg, wireshark


class SubjectCreator(object):
    @staticmethod
    def from_subject(subject, scratch_root='~'):
        cls = SubjectCreator._get_subject_cls(subject)
        return cls(subject.name, subject.remote, scratch_root)

    @staticmethod
    def _get_subject_cls(subject):
        if subject.name.lower() == 'ffmpeg':
            return ffmpeg.FFmpeg
        if subject.name.lower() == 'wireshark':
            return wireshark.Wireshark
        if subject.name.lower() == 'curl':
            return curl.cURL

        raise UnknownSubjectError('Unknown Subject: {0}'.format(subject.name))

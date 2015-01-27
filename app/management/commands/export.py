import os, csv
from optparse import make_option

from django.core.management.base import BaseCommand, CommandError

from app import gitapi, constants
from app.models import *


class Command(BaseCommand):
    # TODO: Add help text to the options.
    option_list = BaseCommand.option_list + (
        make_option('-o', '--output-path',
                    dest='output_path',
                    help='output-path HELP.'),
        make_option('-n', '--name-only',
                    dest='name_only',
                    action='store_true',
                    default=True,
                    help='name-only HELP.'),
        make_option('-r', '--reachable-only',
                    dest='reachable_only',
                    action='store_true',
                    default=False,
                    help='reachable-only HELP.'),
    )
    help = 'export HELP.'

    def handle(self, *args, **options):
        self.out = options.get('output_path')
        self.name_only = bool(options.get('name_only'))
        self.reachable_only = bool(options.get('reachable_only'))

        if self.name_only:
            self.export_based_on_name()
        else:
            self.export_based_on_name_n_file()

    def export_based_on_name(self):
        revs = [
            '0.6.0', '0.7.0', '0.8.0', '0.9.0', '0.10.0',
            '0.11.0', '1.0.0', '1.1.0', '1.2.0', '2.0.0',
            '2.1.0', '2.2.0', '2.3.0', '2.4.0', '2.5.0'
        ]

        with open(os.path.join(self.out, 'epr.csv'), 'w', newline='') as epr_file, \
                open(os.path.join(self.out, 'sepr_one.csv'), 'w', newline='') as sepr_one_file, \
                open(os.path.join(self.out, 'sepr_two.csv'), 'w', newline='') as sepr_two_file:
            epr_writer = csv.writer(epr_file)
            sepr_one_writer = csv.writer(sepr_one_file)
            sepr_two_writer = csv.writer(sepr_two_file)

            epr_writer.writerow(['Name'] + revs)
            sepr_one_writer.writerow(['Name'] + revs)
            sepr_two_writer.writerow(['Name'] + revs)

            for (name,) in Function.objects.filter(is_entry=True).values_list('name').distinct():
                eprs = []
                seprs_two = []
                seprs_one = []

                if Function.objects.filter(name=name, is_entry=True).count() == Revision.objects.filter(
                        is_loaded=True).count():
                    for rev in revs:
                        epr = '-'
                        sepr_one = '-'
                        sepr_two = '-'

                        revision = Revision.objects.get(number=rev, is_loaded=True)
                        n_functions = 0
                        if self.reachable_only:
                            n_functions = revision.num_reachable_functions
                        else:
                            n_functions = revision.num_functions

                        if Function.objects.filter(name=name, revision=revision, is_entry=True).exists():
                            function = Function.objects.filter(name=name, revision=revision, is_entry=True)[:1].get()
                            if Reachability.objects.filter(function=function).exists():
                                epr = str(
                                    Reachability.objects.get(function=function,
                                                             type=constants.RT_DES).value / n_functions)
                                sepr_one = str(Reachability.objects.get(function=function,
                                                                        type=constants.RT_DES_ONE).value / n_functions)
                                sepr_two = str(Reachability.objects.get(function=function,
                                                                        type=constants.RT_DES_TWO).value / n_functions)

                        eprs.append(epr)
                        seprs_one.append(sepr_one)
                        seprs_two.append(sepr_two)

                    epr_writer.writerow([name] + eprs)
                    sepr_one_writer.writerow([name] + seprs_one)
                    sepr_two_writer.writerow([name] + seprs_two)

        with open(os.path.join(self.out, 'expr.csv'), 'w', newline='') as expr_file:
            expr_writer = csv.writer(expr_file)

            expr_writer.writerow(['Name'] + revs)

            for (name,) in Function.objects.filter(is_exit=True).values_list('name').distinct():
                exprs = []

                if Function.objects.filter(name=name, is_exit=True).count() == Revision.objects.filter(
                        is_loaded=True).count():
                    for rev in revs:
                        expr = '-'

                        revision = Revision.objects.get(number=rev, is_loaded=True)
                        n_functions = 0
                        if self.reachable_only:
                            n_functions = revision.num_reachable_functions
                        else:
                            n_functions = revision.num_functions

                        if Function.objects.filter(name=name, revision=revision, is_exit=True).exists():
                            function = Function.objects.filter(name=name, revision=revision, is_exit=True)[:1].get()
                            if Reachability.objects.filter(function=function).exists():
                                expr = str(
                                    Reachability.objects.get(function=function,
                                                             type=constants.RT_ANC).value / n_functions)
                        exprs.append(expr)

                    expr_writer.writerow([name] + exprs)

    def export_based_on_name_n_file(self):
        revs = [
            '0.6.0', '0.7.0', '0.8.0', '0.9.0', '0.10.0',
            '0.11.0', '1.0.0', '1.1.0', '1.2.0', '2.0.0',
            '2.1.0', '2.2.0', '2.3.0', '2.4.0', '2.5.0'
        ]

        with open(os.path.join(self.out, 'epr.csv'), 'w', newline='') as epr_file, open(
                os.path.join(self.out, 'sepr.csv'), 'w', newline='') as sepr_file:
            epr_writer = csv.writer(epr_file)
            sepr_writer = csv.writer(sepr_file)

            epr_writer.writerow(['Name', 'File'] + revs)
            sepr_writer.writerow(['Name', 'File'] + revs)

            for (name, file) in Function.objects.filter(is_entry=True).values_list('name', 'file').distinct():
                eprs = []
                seprs = []

                for rev in revs:
                    epr = '-'
                    sepr = '-'

                    revision = Revision.objects.get(number=rev, is_loaded=True)
                    if Function.objects.filter(name=name, file=file, revision=revision, is_entry=True).exists():
                        function = Function.objects.get(name=name, file=file, revision=revision, is_entry=True)
                        if Reachability.objects.filter(function=function).exists():
                            epr = str(Reachability.objects.get(function=function, type=constants.RT_EPR).value)
                            sepr = str(Reachability.objects.get(function=function, type=constants.RT_SEPR).value)
                    eprs.append(epr)
                    seprs.append(sepr)

                epr_writer.writerow([name, file] + eprs)
                sepr_writer.writerow([name, file] + seprs)

        with open(os.path.join(self.out, 'expr.csv'), 'w', newline='') as expr_file:
            expr_writer = csv.writer(expr_file)

            expr_writer.writerow(['Name', 'File'] + revs)

            for (name, file) in Function.objects.filter(is_exit=True).values_list('name', 'file').distinct():
                exprs = []

                for rev in revs:
                    expr = '-'

                    revision = Revision.objects.get(number=rev, is_loaded=True)
                    if Function.objects.filter(name=name, file=file, revision=revision, is_exit=True).exists():
                        function = Function.objects.get(name=name, file=file, revision=revision, is_exit=True)
                        if Reachability.objects.filter(function=function).exists():
                            expr = str(Reachability.objects.get(function=function, type=constants.RT_EXPR).value)
                    exprs.append(expr)

                expr_writer.writerow([name, file] + exprs)
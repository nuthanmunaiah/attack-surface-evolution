import os, csv
from optparse import make_option

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from app import gitapi, constants
from app.models import *


class Command(BaseCommand):
    # TODO: Add help text to the options.
    option_list = BaseCommand.option_list + (
        make_option('-o', '--output-path',
                    dest='output_path',
                    help='output-path HELP.'),
        make_option('-c', '--common-across',
                    dest='common_across',
                    action='store_true',
                    default=False,
                    help='common-across HELP.'),
        make_option('-n', '--name-only',
                    dest='name_only',
                    action='store_true',
                    default=True,
                    help='name-only HELP.'),
    )
    help = 'export HELP.'

    def handle(self, *args, **options):
        self.out = options.get('output_path')
        self.name_only = bool(options.get('name_only'))
        self.common_across = bool(options.get('common_across'))

        self.export()

    def export(self):
        _revisions = [
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

            epr_writer.writerow(['Name'] + _revisions)
            sepr_one_writer.writerow(['Name'] + _revisions)
            sepr_two_writer.writerow(['Name'] + _revisions)

            for name in self.get_function_names(type='entry', common_across=self.common_across):
                eprs = []
                seprs_two = []
                seprs_one = []

                for _revision in _revisions:
                    epr = '-'
                    sepr_one = '-'
                    sepr_two = '-'

                    revision = Revision.objects.get(number=_revision, is_loaded=True)

                    if Function.objects.filter(name=name, revision=revision, is_entry=True).exists():
                        function = Function.objects.filter(name=name, revision=revision, is_entry=True)[:1].get()
                        if Reachability.objects.filter(function=function).exists():
                            epr = str(
                                Reachability.objects.get(function=function,
                                                         type=constants.RT_EN).value)
                            sepr_one = str(Reachability.objects.get(function=function,
                                                                    type=constants.RT_SHEN_ONE).value)
                            sepr_two = str(Reachability.objects.get(function=function,
                                                                    type=constants.RT_SHEN_TWO).value)

                    eprs.append(epr)
                    seprs_one.append(sepr_one)
                    seprs_two.append(sepr_two)

                epr_writer.writerow([name] + eprs)
                sepr_one_writer.writerow([name] + seprs_one)
                sepr_two_writer.writerow([name] + seprs_two)

        with open(os.path.join(self.out, 'expr.csv'), 'w', newline='') as expr_file:
            expr_writer = csv.writer(expr_file)

            expr_writer.writerow(['Name'] + _revisions)

            for name in self.get_function_names(type='exit', common_across=self.common_across):
                exprs = []

                for _revision in _revisions:
                    expr = '-'

                    revision = Revision.objects.get(number=_revision, is_loaded=True)

                    if Function.objects.filter(name=name, revision=revision, is_exit=True).exists():
                        function = Function.objects.filter(name=name, revision=revision, is_exit=True)[:1].get()
                        if Reachability.objects.filter(function=function).exists():
                            expr = str(
                                Reachability.objects.get(function=function,
                                                         type=constants.RT_EX).value)
                    exprs.append(expr)

                expr_writer.writerow([name] + exprs)

    def get_function_names(self, type, common_across=True):
        if type not in ('entry', 'exit'):
            raise CommandError('%s is not valid for argument type. Should be entry or exit.' % type)

        query = None
        if common_across:
            if type == 'entry':
                query = '''
                        select f.name, count(*)
                        from app_function f join app_reachability r on r.function_id = f.id
                        where name in
                            (
                                select distinct(name)
                                from app_function
                                where is_entry = true
                            )
                            and r.type = 'en'
                        group by f.name
                        having count(*) = (select count(*) from app_revision where is_loaded = true);
                    '''
            elif type == 'exit':
                query = '''
                        select f.name, count(*)
                        from app_function f join app_reachability r on r.function_id = f.id
                        where name in
                            (
                                select distinct(name)
                                from app_function
                                where is_exit = true
                            )
                            and r.type = 'ex'
                        group by f.name
                        having count(*) = (select count(*) from app_revision where is_loaded = true);
                    '''
            cursor = connection.cursor()
            cursor.execute(query)
            return [name for (name, count) in cursor.fetchall()]
        else:
            if type == 'entry':
                return [name for (name, ) in Function.objects.filter(is_entry=True).values_list('name').distinct()]
            elif type == 'exit':
                return [name for (name, ) in Function.objects.filter(is_exit=True).values_list('name').distinct()]
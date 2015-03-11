import os
import sys
from django.conf import settings
from django.template.loader import render_to_string

from rpy2 import robjects

from app.models import Revision, Function

# Aliasing the robjects.r singleton
r = robjects.r

def run():
	status = 0

	try:
		db_connect()

		results = dict()
		results['revisions'] = list()
		# TODO: Remove call to exclude()
		for revision in Revision.objects.filter(is_loaded=True).exclude(
			number='0.6.0').order_by('id'):

			result = dict()
			result['number'] = revision.number

			db_query(revision)

			result['pten'] = association('proximity_to_entry',
				'is_vulnerable', normalize=False)
			result['ptex'] = association('proximity_to_exit',
				'is_vulnerable', normalize=False)
			result['scen'] = association('surface_coupling_with_entry',
				'is_vulnerable')
			result['scex'] = association('surface_coupling_with_exit',
				'is_vulnerable')

			results['revisions'].append(result)

		with open(settings.OUTPUT_FILE, 'w+') as _file:
			_file.write(render_to_string('app/r.md', results))
	except Exception as e:
		sys.stderr.write(e)
		status = 2
	finally:
		db_disconnect()

	return status

def db_connect():
	# TODO: Allow for other providers
	rcode = '''
		library("DBI")
		library("RPostgreSQL")
		driver <- dbDriver("PostgreSQL")
		connection <- dbConnect(driver,
			host="%(HOST)s",
			port=%(PORT)s,
			user="%(USER)s",
			password="%(PASSWORD)s",
			dbname="%(NAME)s"
		)
	''' % (settings.DATABASES['default'])

	r(rcode)

def db_disconnect():
	r('dbDisconnect(connection)')

def db_query(revision):
	rcode = '''
		dataset <- dbGetQuery(connection,
					"SELECT * FROM app_function	WHERE revision_id = %d")
	''' % (revision.id)

	r(rcode)
	
def association(column, switch, normalize=True):
	params = {'column': column, 'switch': switch}

	if normalize:
		rcode = '''
			vulnerable <- dataset$%(column)s[dataset$%(switch)s == "TRUE" & 
				is.finite(dataset$%(column)s)]
			neutral <- dataset$%(column)s[dataset$%(switch)s == "FALSE" & 
				is.finite(dataset$%(column)s)]

			vulnerable <- vulnerable / 
				dataset$sloc[dataset$%(switch)s == "TRUE" & 
					is.finite(dataset$%(column)s)]
			neutral <- neutral / 
				dataset$sloc[dataset$%(switch)s == "FALSE" & 
					is.finite(dataset$%(column)s)]

			vulnerable <- vulnerable[is.finite(vulnerable)]
			neutral <- neutral[is.finite(neutral)]

			htest <- wilcox.test(vulnerable, neutral)
			
			p <- htest$p.value
	    	v_mean <- mean(vulnerable)
	    	n_mean <- mean(neutral)
	    	v_median <- median(vulnerable)
	    	n_median <- median(neutral)
		''' % (params)
	else:
		rcode = '''
			vulnerable <- dataset$%(column)s[dataset$%(switch)s == "TRUE" & 
				is.finite(dataset$%(column)s)]
			neutral <- dataset$%(column)s[dataset$%(switch)s == "FALSE" & 
				is.finite(dataset$%(column)s)]

			htest <- wilcox.test(vulnerable, neutral)
			
			p <- htest$p.value
	    	v_mean <- mean(vulnerable)
	    	n_mean <- mean(neutral)
	    	v_median <- median(vulnerable)
	    	n_median <- median(neutral)
		''' % (params)

	r(rcode)

	result = {
		'p': r['p'][0],
		'mean': {'vuln': r['v_mean'][0], 'neut': r['n_mean'][0]},
		'median': {'vuln': r['v_median'][0], 'neut': r['n_median'][0]}
	}

	return result

if __name__ == '__main__':
	run()

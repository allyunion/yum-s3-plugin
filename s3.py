"""
Yum plugin for Amazon S3 access.

This plugin provides access to a protected Amazon S3 bucket using either boto
or Amazon's REST authentication scheme.

On CentOS this file goes into /usr/lib/yum-plugins/s3.py

You will also need two configuration files.   See s3.conf and s3test.repo for
examples on how to deploy those.


"""

#   Copyright 2011, Robert Mela
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

#   This fork of the plugin only uses UrlGrabber and does not depend on python-boto

import logging
import os
import sys
import urllib
import urllib2
import time
import hmac
import base64

from yum.plugins import TYPE_CORE
from yum.yumRepo import YumRepository
from yum import config
from yum import logginglevels

import yum.Errors

# This plugin's revision number
__revision__ = "1.1.2"

##### Set up Yum Plugin #####

requires_api_version = '2.5'
plugin_type = TYPE_CORE
CONDUIT=None

def config_hook(conduit):
	config.RepoConf.s3_enabled = config.BoolOption(False)
	config.RepoConf.key_id = config.Option() or conduit.confString('main', 'aws_access_key_id')
	config.RepoConf.secret_key = config.Option() or conduit.confString('main', 'aws_secret_access_key')

def init_hook(conduit):
	"""
	Plugin initialization hook. Setup the S3 repositories.
	"""

	repos = conduit.getRepos()
	for key,repo in repos.repos.iteritems():
		if isinstance(repo, YumRepository) and repo.s3_enabled and repo.enabled:
			new_repo = AmazonS3Repo(key)
			new_repo.name = repo.name
			new_repo.baseurl = repo.baseurl
			new_repo.mirrorlist = repo.mirrorlist
			new_repo.basecachedir = repo.basecachedir
			if hasattr(repo, 'base_persistdir'):
				new_repo.base_persistdir = repo.base_persistdir
			new_repo.gpgcheck = repo.gpgcheck
			new_repo.proxy = repo.proxy
			new_repo.enablegroups = repo.enablegroups
			new_repo.key_id = repo.key_id
			new_repo.secret_key = repo.secret_key
			repos.delete(repo.id)
			repos.add(new_repo)

class UrllibGrabber:
	def __init__(self, awsAccessKey, awsSecretKey, baseurl ):
		self.logger = logging.getLogger("yum.verbose.main")
		try:
			baseurl = baseurl[0]
		except:
			pass
		self.baseurl = baseurl
		self.awsAccessKey = awsAccessKey
		self.awsSecretKey = awsSecretKey

	def s3sign(self, cls, request, secret_key, key_id, date=None):
		self.logger.log(logginglevels.DEBUG_4, "s3: Signing S3 URL...")
       		date=time.strftime("%a, %d %b %Y %H:%M:%S +0000", date or time.gmtime() )
       		host = request.get_host()
       		bucket = host.split('.')[0]
       		request.add_header( 'Date', date)
       		resource = "/%s%s" % ( bucket, request.get_selector() )
       		sigstring = """%(method)s\n\n\n%(date)s\n%(canon_amzn_resource)s""" % {
		                               'method':request.get_method(),
		                               #'content_md5':'',
		                               #'content_type':'', # only for PUT
		                               'date':request.headers.get('Date'),
		                               #'canon_amzn_headers':'',
		                               'canon_amzn_resource':resource }
		try:
			import hashlib
			digest = hmac.new(secret_key, sigstring, hashlib.sha1 ).digest()
		except:
			import sha
       			digest = hmac.new(secret_key, sigstring, sha ).digest()
       		digest = base64.b64encode(digest)
       		request.add_header('Authorization', "AWS %s:%s" % ( key_id,  digest ))

	def _request(self,url):
		from urllib import quote
		self.logger.log(logginglevels.DEBUG_4, "s3: Requesting URL: %s%s" % (self.baseurl, quote(url)))
		req = urllib2.Request("%s%s" % (self.baseurl, quote(url)))
		self.s3sign(self, req, self.awsSecretKey, self.awsAccessKey )
		return req

	def urlgrab(self, url, filename=None, **kwargs):
		"""urlgrab(url) copy the file to the local filesystem"""
		self.logger.log(logginglevels.DEBUG_4, "s3: UrlLibGrabber urlgrab url=%s filename=%s" % ( url, filename ))
		req = self._request(url)
		if not filename:
			filename = req.get_selector()
			if filename[0] == '/':
				filename = filename[1:]
		out = open(filename, 'w+')
		try:
			resp = urllib2.urlopen(req)
			buff = resp.read(8192)
			while buff:
				out.write(buff)
				buff = resp.read(8192)
		except urllib2.HTTPError, e:
			self.logger.critical("s3: While grabbing url=%s filename=%s, urllib2 returned: %s" % ( url, filename, e ))
			raise yum.Errors.RepoError('s3: urllib2: %s' % e)
		except socket.error, e:
			self.logger.critical("s3: While grabbing url=%s filename=%s, received a socket error: %s" % ( url, filename, e ))
			raise
		except socket.gaierror, e:
			self.logger.critical("s3: While grabbing url=%s filename=%s, received a socket error: %s" % ( url, filename, e ))
			raise
		except socket.timeout, e:
			self.logger.critical("s3: While grabbing url=%s filename=%s, received a socket error: %s" % ( url, filename, e ))
			raise
		except KeyboardInterrupt:
			raise
		except:
			self.logger.critical("s3: While grabbing url=%s filename=%s, received an unknown error!")
			raise
			
		return filename
		# zzz - does this return a value or something?

	def urlopen(self, url, **kwargs):
		"""urlopen(url) open the remote file and return a file object"""
		return urllib2.urlopen( self._request(url) )

	def urlread(self, url, limit=None, **kwargs):
		"""urlread(url) return the contents of the file as a string"""
		return urllib2.urlopen( self._request(url) ).read()

##### Yum Repository Definition for Amazon S3 Repositories #####

class AmazonS3Repo(YumRepository):
	"""
	Repository object for Amazon S3.
	"""

	def __init__(self, repoid):
		YumRepository.__init__(self, repoid)
		self.enable()
		self.grabber = None

	def setupGrab(self):
		YumRepository.setupGrab(self)
		logger = logging.getLogger("yum.verbose.main")
		logger.log(logginglevels.DEBUG_4, "s3: Creating UrllibGrabber")
		self.grabber = UrllibGrabber(self.key_id, self.secret_key, self.baseurl)

	def _getgrabfunc(self):
		raise Exception("get grabfunc!")

	def _getgrab(self):
		if not self.grabber:
			self.grabber = UrllibGrabber(self.key_id, self.secret_key, baseurl=self.baseurl )
		return self.grabber

	grabfunc = property(lambda self: self._getgrabfunc())
	grab = property(lambda self: self._getgrab())


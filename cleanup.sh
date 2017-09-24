PMOD="clever-clown"
SPOJ_MOD="spoton-johny"
VENV="venv"
PROJECT_BASE="/research_data/code/git/"
PROJECT=$PROJECT_BASE/$PMOD/

VIRTUAL_ENV=$PROJECT/$VENV
PYTHON=$VIRTUAL_ENV"/bin/python"
# cleanup local directory


rm -r $VIRTUAL_ENV/dist-packages/$PMOD-1.0-py2.7.egg \
      $PROJECT/src/$PMOD.egg-info/ \
      $PROJECT/dist/ \
      $PROJECT/build/

rm -r $VIRTUAL_ENV

#virtualenv -p /usr/bin/python2.7 $VIRTUAL_ENV
#$PYTHON $PROJECT_BASE/$SPOJ/setup.py install
#$PYTHON setup.py install


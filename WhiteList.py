#!/usr/bin/python
import json
import datetime

class WhiteList:
    def __init__( self, path ):
        self.whitelist = dict()
        self.filepath = path
        self.load_list()

    def load_list( self ):
        try:
            wlfile = open( self.filepath, 'r' )
            self.whitelist = json.load( wlfile )
            wlfile.close()
        except IOError:
            self.save_list()

    def save_list( self ):
        try:
            wlfile = open( self.filepath, 'w' )
            json.dump( self.whitelist, wlfile )
            wlfile.close()
        except IOError:
            print( "Cannot write to whitelist file: ", self.filepath )

    def __iter__( self ):
        return iter( self.whitelist )

    def set( self, k, v ):
        self.whitelist[k] = v

    def get( self, k ):
        return self.whitelist.get( k, None )

    def pop( self, k ):
        return self.whitelist.pop( k, None )

    def exists( self, k ):
        return k in self.whitelist

    def cleanup( self, comp ):
        expireds = list()
        for k in self.whitelist:
            if comp( self.whitelist[k] ):
                expireds.append( k )
        for k in expireds:
            self.whitelist.pop( k )


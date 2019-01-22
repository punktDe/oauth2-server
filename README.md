# OAuth 2.0 Server for the Flow Framework

[![Latest Stable Version](https://poser.pugx.org/punktde/oauth2-server/v/stable)](https://packagist.org/packages/punktde/oauth2-server) [![Total Downloads](https://poser.pugx.org/punktde/oauth2-server/downloads)](https://packagist.org/packages/punktde/oauth2-server)

This [Flow](https://flow.neos.io) package provides an OAuth 2.0 server, based on [The PHP League OAuth Server](https://oauth2.thephpleague.com/).

# Setup

## Installation

The installation is done with composer:

	composer require punktde/oauth2-server
	
Run the doctrine migrations
	
	./flow doctrine:migrate

## Configuration

Enable the required grant types within your settings:

	PunktDe:
	  OAuth2:
	    Server:
	      grantTypes:
	        client_credentials:
	          enabled: false
	        authorization_code:
	          enabled: false

Generate server keys:

	./flow oauthserver:generateserverkeys

Create client credentials:

	./flow oauthserver:createclientcredentials <identifier> <name> <grant-type>
	
# Implemented Grants

There is a good listing at [thephpleague.com](https://oauth2.thephpleague.com/authorization-server/which-grant/) of all grant types of OAuth2 which should help you to find the type that fits to your application.

The following OAuth 2.0 grant types are implemented:

## Client credentials Grant

If you are authorizing a machine to access resources and you don’t require the permission of a user to access said resources you should implement the client credential grant.

## Authorization code grant

If the client is a web application that has a server side component then you should implement the authorization code grant.

The urls to use are: 

* Access Token URL: `<YourDomain>/oauth/token`
* Authorization URL `<YourDomain>/oauth/authorize`

The Authorization code grant is currently implemented with an implicit authorization of the requesting application.

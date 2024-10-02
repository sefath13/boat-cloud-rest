## Boat REST API - README
_A Flask web application that implements a RESTful API for Boat and Load entities hosted on the Google Cloud Platform_
____
**Fall 2023 OSU CS493 Cloud Application Development Portfolio Project**

### Features:
- REST API that uses proper resource based URLs, pagination and status codes.
- System to create user accounts for authentication and authorization.
- Utilize Google Cloud Platform Datastore to store resources
- Deploy project using Google App Engine
- Collection with Postman to test REST API functionality

### Data Model:
The app stores three kinds of entities in Datastore: Users and two non-user entities: Boats and Loads. 

#### User Entities

Property | Required? | Data Type | Notes 
--- | --- | --- | --- 
id | Datastore generated | Integer | The id of the user. Datastore automatically generates it. | 
user_name | yes | String | User’s email from Auth0 | 
user_id | yes | String | User’s id to identify who owns the boat. It is the ‘sub’ property of the ‘userinfo’ property from the jwt obtained when a user creates an account. Example: ‘auth0|8o34naq8765efc8jl89df92p’ | 
self | self generated | String | Self-link that goes to the most direct location to find the user. Cannot store in Datastore, must be generated each time. | 

#### Boat Entity

Property | Required? | Data Type | Notes 
--- | --- | --- | --- 
id | Datastore generated | Integer | The id of the boat. Datastore automatically generates it. | 
name | yes | String | Name of the boat | 
type | yes | String | Type of boat | 
length | yes | String | Length of boat in feet | 
loads | no | List | Loads of the boat, embedded list. Each load has ID and self-URL. Can be empty when creating boat. | 
owner | yes | string | Boats can only be created, deleted, read, and updated by the associated user and JWT. User’s id will be updated here when each boat is created. | 
self | self generated | String | Self-link that goes to the most direct location to find the user. Cannot store in Datastore, must be generated each time. | 

#### Load Entity

Property | Required? | Data Type | Notes 
--- | --- | --- | --- 
id | Datastore generated | Integer | The id of the load. Datastore automatically generates it. | 
volume | yes | Integer | The volume of the load | 
carrier | no | Dictionary | The boat carrying the load. ID and self-URL. Can be ‘null’ at creation. | 
item | yes | String | Item type of load like 'Toys' or 'Shoes' |
creation_date | yes | String | Date load was created |
self | self generated | String | Self-link that goes to the most direct location to find the user. Cannot store in Datastore, must be generated each time. | 

### Authorized Users:
This API is only accessible once users create an account using the OAuth login process through Auth0. Once the user is authenticated, they will receive a JWT token that they can use to show they are authorized to access their resources only through the API web application. 

### All possible endpoints at https://khanse-project.wn.r.appspot.com:

* These endpoints need authorization from the owner/user, which the user has in the form of their JWT.

Method | Endpoint | Authorization | Notes 
--- | --- | --- | --- 
POST | /boats | JWT (Bearer Token) | Create a boat.
GET | /boats/:boat_id | JWT (Bearer Token) | View a boat.
GET | /boats | JWT (Bearer Token) | View all boats for authorized user.
PUT | /boats/:boat_id | JWT (Bearer Token) | Edit a boat. Updates all fields. 
PATCH | /boats/:boat_id | JWT (Bearer Token) | Edit a boat. Updates only edited fields. 
DELETE | /boats/:boat_id | JWT (Bearer Token) | Delete a boat. If load was on this boat, load will be reassigned to have no carrier.
PUT | /boats/:boat_id/loads/:load_id | JWT (Bearer Token) | Load is assigned to boat. 
DELETE | /boats/:boat_id/loads/:load_id | JWT (Bearer Token) | Boat should have load deleted from ‘loads’ list and load deleted from all loads
GET | /users | None | Get all users for website.
___
* These endpoints do not need authorization from the owner/user.
  
Method | Endpoint | Authorization | Notes 
--- | --- | --- | --- 
POST | /loads | None | Create a load.
GET | /loads/:load_id | None | View a load.
GET | /loads | None | View all loads for authorized user.
PUT | /loads/:load_id | None | Edit a load. Updates all fields. 
PATCH | /loads/:load_id | None | Edit a load. Updates only edited fields. 
DELETE | /load/:load_id | None | Delete a load. If the load had a boat carrier, boat will lose the load. 

### Credits
* [Auth0 Login for Python Flask App](https://auth0.com/docs/quickstart/webapp/python/interactive)
* Source Material from OSU CS493 Material and Guidelines


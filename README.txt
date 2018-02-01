READ ME

-Project Title:
 Item Catalog

-What is this project?
 Once you open localhost:5000 you will be displyed
	1. login button - which allows you to login with either google sign in or by entering 
	    		  your username and password
 	2. Display the list of categories
	3. Recently added items

How it works?
Setup:
	Prior to running the catalog_view.py file you need to set up the database
	run catalog_db.py either from the terminal by going to the folder of this file or go to pycharm and click 	on run
	

After downloading all the files
	1. Run catalog_view.py file which takes you to the haome page.
	2. Login button takes you to the login page where you can login using your google account 
	   or by username or password
	3. If you dont have a username or password you can register usinh the New User link 	   provided in the login page
	4. Once the loin is successfull you will be redirected to the home page, where you have 	the list of categories and the recently added items
	5. You can click on any of the caategories to see the items in that particular category
	6. you can click on the items to see the item description, and can perform edit and 	delete operations. But only a logged in user can perform these operations
	7. On the page, only if you are logged in you can add new categories to the already 	existing ones and add items 
	8.You have a logout functionality.

-Contents:
	1. catalog_view.py
	2.catalog_db.py
	3. HTML files in the template folder
	4. CSS and images in Static folder
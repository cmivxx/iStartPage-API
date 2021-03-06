<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();

        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password'));

            $response = array();

            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');

            // validating email address
            validateEmail($email);

            $db = new DbHandler();
            $res = $db->createUser($name, $email, $password);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['name'] = $user['name'];
                    $response['email'] = $user['email'];
                    $response['apiKey'] = $user['api_key'];
                    $response['createdAt'] = $user['created_at'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Login failed. Incorrect credentials';
            }

            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */

$app->get('/feeds', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getAllUserFeeds($user_id);

            $response["error"] = false;
            $response["feeds"] = array();

            // looping through result and preparing tasks array
            while ($task = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["idnum"] = $task["idnum"];
                $tmp["name"] = $task["name"];
                $tmp["url"] = html_entity_decode($task["url"]);
                $tmp["rss"] = html_entity_decode($task["rss"]);
                array_push($response["feeds"], $tmp);
            }

            echoRespnse(200, $response);
        });

/**
 * Listing single feed of particual user
 * method GET
 * url /feeds/:id
 * Will return 404 if the task doesn't belong to user
 */
$app->get('/feeds/:id', 'authenticate', function($feed_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getFeed($feed_id, $user_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["idnum"] = $result["idnum"];
                $response["name"] = $result["name"];
                $response["url"] = $result["url"];
                $response["rss"] = $result["rss"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Creating new feed in db
 * method POST
 * params - name
 * url - /tasks/
 */
$app->post('/feeds', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name'));

            $response = array();
            $name = $app->request->post('name');
            $url = $app->request->post('url');
            $rss = $app->request->post('rss');

            global $user_id;
            $db = new DbHandler();

            // creating new task
            $feed_id = $db->createFeed($user_id, $name, $url, $rss);

            if ($task_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Feed created successfully";
                $response["task_id"] = $task_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create feed. Please try again";
                echoRespnse(200, $response);
            }            
        });

/**
 * Updating existing task
 * method PUT
 * params task, status
 * url - /tasks/:id
 */
$app->put('/feeds/:id', 'authenticate', function($feed_id) use($app) {
            // check for required params
            verifyRequiredParams(array('name', 'url', 'rss'));

            global $user_id;            
            $name = $app->request->put('name');
            $url = $app->request->put('url');
            $rss = $app->request->put('rss');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateTask($user_id, $feed_id, $name, $url, $rss);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "Feed updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "Feed failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Deleting feed. Users can delete only their feeds
 * method DELETE
 * url /feeds
 */
$app->delete('/feeds/:id', 'authenticate', function($feed_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteTask($user_id, $feed_id);
            if ($result) {
                // task deleted successfully
                $response["error"] = false;
                $response["message"] = "Feed deleted succesfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Feed failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

$app->run();
?>
<?php

use Slim\App;

return function (App $app) {
    // e.g: $app->add(new \Slim\Csrf\Guard);

    // middleware untuk validasi api key
    $app->add(function ($request, $response, $next) {
    
        $key = $request->getQueryParam("key");
        
    
        if(!isset($key)){
            return $response->withJson(["status" => "API Key required"], 401);
        }
        
        $sql = "SELECT * FROM aset_api WHERE api_key=:api_key";
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':api_key', $key, PDO::PARAM_STR);
        $stmt->execute();
        
        if($stmt->rowCount() > 0){ 
            $result = $stmt->fetch();
            if($key == $result["api_key"]){
            
                // update hit
                $sql = "UPDATE aset_api SET hit=hit+1 WHERE api_key=:api_key";
                $stmt = $this->db->prepare($sql);
                $stmt->bindParam(':api_key', $key, PDO::PARAM_STR);
                $stmt->execute();
                
                return $response = $next($request, $response);
            }
        }
        
        return $response->withJson(["status" => "Unauthorized"], 401);
    });
};

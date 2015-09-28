/*
 * Copyright 2010 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * 
 * Modified by Sambit Sahu
 * Modified by Kyung-Hwa Kim (kk2515@columbia.edu)
 * 
 * 
 */
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.PropertiesCredentials;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairResult;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateTagsRequest;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.ec2.model.DescribeImagesResult;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.DescribeKeyPairsResult;
import com.amazonaws.services.ec2.model.Image;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.InstanceState;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.KeyPair;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;
import com.amazonaws.services.ec2.model.StartInstancesRequest;
import com.amazonaws.services.ec2.model.StopInstancesRequest;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.ec2.model.TerminateInstancesRequest;


public class AwsSample {

    /*
     * Important: Be sure to fill in your AWS access credentials in the
     *            AwsCredentials.properties file before you try to run this
     *            sample.
     * http://aws.amazon.com/security-credentials
     */

    static AmazonEC2      ec2;

    public static void main(String[] args) throws Exception {


    	 AWSCredentials credentials = new PropertiesCredentials(
    			 AwsSample.class.getResourceAsStream("AwsCredentials.properties"));

         /*********************************************
          * 
          *  #1 Create Amazon Client object
          *  
          *********************************************/
    	 System.out.println("#1 Create Amazon Client object");
         ec2 = new AmazonEC2Client(credentials);

         
       
        try {
        	
        	/*********************************************
        	 * 
             *  #2 Describe Availability Zones.
             *  
             *********************************************/
        	System.out.println("#2 Describe Availability Zones");
            DescribeAvailabilityZonesResult availabilityZonesResult = ec2.describeAvailabilityZones();
            System.out.println("You have access to " + availabilityZonesResult.getAvailabilityZones().size() +
                    " Availability Zones.");

            /*********************************************
             * 
             *  #3 Describe Available Images
             *  
             *********************************************/
            System.out.println("#3 Describe Available Images");
            DescribeImagesResult dir = ec2.describeImages();
            List<Image> images = dir.getImages();
            System.out.println("You have " + images.size() + " Amazon images");
            
            
            /*********************************************
             *                 
             *  #4 Describe Key Pair
             *                 
             *********************************************/
            System.out.println("#4 Describe Key Pair");
            DescribeKeyPairsResult dkr = ec2.describeKeyPairs();
            System.out.println(dkr.toString());
            
            /*********************************************
             * 
             *  #5 Describe Current Instances
             *  
             *********************************************/
            System.out.println("#5 Describe Current Instances");
            DescribeInstancesResult describeInstancesRequest = ec2.describeInstances();
            List<Reservation> reservations = describeInstancesRequest.getReservations();
            Set<Instance> instances = new HashSet<Instance>();
            // add all instances to a Set.
            for (Reservation reservation : reservations) {
            	instances.addAll(reservation.getInstances());
            }
            
            System.out.println("You have " + instances.size() + " Amazon EC2 instance(s).");
            for (Instance ins : instances){
            	
            	// instance id
            	String instanceId = ins.getInstanceId();
            	
            	// instance state
            	InstanceState is = ins.getState();
            	System.out.println(instanceId+" "+is.getName());
            }
            
            /*********************************************
             * 
             *  #6 Create an Instance
             *  
             *********************************************/
            System.out.println("#6 Create an Instance");
            String imageId = "ami-76f0061f"; // Basic 32-bit Amazon Linux AMI
            int minInstanceCount = 1; // create 1 instance
            int maxInstanceCount = 1;
            RunInstancesRequest rir = new RunInstancesRequest(imageId, minInstanceCount, maxInstanceCount);
            
            // Create a new security group
            String testGroup = "testSecurityGroup";
            
            try {
                CreateSecurityGroupRequest securityGroupRequest =
                    new CreateSecurityGroupRequest(testGroup, "Security Group Test");
                ec2.createSecurityGroup(securityGroupRequest);
                System.out.println("The security group '" + testGroup + "has been created.");
            } catch (AmazonServiceException ase) {
                // Likely this means that the group is already created, so continue.
                System.out.println(ase.getMessage());
            }
            
            String ipAddr = "0.0.0.0/0";

//            // Get the IP of the current host, so that we can limit the Security Group
//            // by default to the ip range associated with your subnet.
//            try {
//                InetAddress addr = InetAddress.getLocalHost();
//
//                // Get IP Address
//                ipAddr = addr.getHostAddress()+"/10";
//            } catch (UnknownHostException e) {
//            }

            // Create a range that you would like to populate.
            ArrayList<String> ipRanges = new ArrayList<String>();
            ipRanges.add(ipAddr);
            
	        // Open up port 22 for TCP traffic to the associated IP from
	        // above (e.g. ssh traffic).
	        IpPermission sshPermission = new IpPermission();
	        sshPermission.setIpProtocol("tcp");
	        sshPermission.setFromPort(new Integer(22));
	        sshPermission.setToPort(new Integer(22));
	        sshPermission.setIpRanges(ipRanges);
	
	        // Open up port 80 for TCP traffic to the associated IP from
	        // above (e.g. http traffic).
	        IpPermission httpPermission = new IpPermission();
	        httpPermission.setIpProtocol("tcp");
	        httpPermission.setFromPort(new Integer(80));
	        httpPermission.setToPort(new Integer(80));
	        httpPermission.setIpRanges(ipRanges);
	
	        // Open up port 443 for TCP traffic to the associated IP from
	        // above (e.g. https traffic).
	        IpPermission httpsPermission = new IpPermission();
	        httpsPermission.setIpProtocol("tcp");
	        httpsPermission.setFromPort(new Integer(443));
	        httpsPermission.setToPort(new Integer(443));
	        httpsPermission.setIpRanges(ipRanges);
	
	        // Open up ports 0 to 65535 for TCP traffic to the associated IP from
	        // above (e.g. tcp traffic).
	        IpPermission tcpPermission = new IpPermission();
	        tcpPermission.setIpProtocol("tcp");
	        tcpPermission.setFromPort(new Integer(0));
	        tcpPermission.setToPort(new Integer(65535));
	        tcpPermission.setIpRanges(ipRanges);
            
	        ArrayList<IpPermission> ipPermissions = new ArrayList<IpPermission>();
	        ipPermissions.add(sshPermission);
	        ipPermissions.add(httpPermission);
	        ipPermissions.add(httpsPermission);
	        ipPermissions.add(tcpPermission);
	        
	        try {
	            // Authorize the ports to the used.
	            AuthorizeSecurityGroupIngressRequest ingressRequest =
	                new AuthorizeSecurityGroupIngressRequest(testGroup,ipPermissions);
	            ec2.authorizeSecurityGroupIngress(ingressRequest);
	            System.out.println("Access control defined to allow SSH, HTTP, HTTPS, and TCP connections.");
	        } catch (AmazonServiceException ase) {
	            // Ignore because this likely means the zone has already
	            // been authorized.
	            System.out.println(ase.getMessage());
	        }
	         
	        String testKey = "testKey";

	        try {
		        // Create and initialize a CreateKeyPairRequest instance.
		        CreateKeyPairRequest createKeyPairRequest = new CreateKeyPairRequest();
		        createKeyPairRequest.withKeyName(testKey);
		        // Pass the request object to the createKeyPair method.
		        // The method returns a CreateKeyPairResult instance.
		        CreateKeyPairResult createKeyPairResult =
		        		  ec2.createKeyPair(createKeyPairRequest);
		        // Call the result object's getKeyPair method to obtain a KeyPair object.
		        // Call the KeyPair object's getKeyMaterial method to obtain the unencrypted
		        // PEM-encoded private key.
		        KeyPair keyPair = new KeyPair();
		        keyPair = createKeyPairResult.getKeyPair();
		        String privateKey = keyPair.getKeyMaterial();
		        
		        String filename = ("./" + keyPair.getKeyName() + ".pem");
		        FileWriter pemfile = new FileWriter(filename);
		        BufferedWriter output = new BufferedWriter(pemfile);
		        output.write(privateKey);
		        output.close();
		   
		        System.out.println("New key pair has been created and saved to " + filename);
		        System.out.println("Fingerprint: " + keyPair.getKeyFingerprint());
	        } catch (AmazonServiceException ase) {
	            // Ignore because this likely means the keypair already exists.
	            System.out.println("Caught Exception: " + ase.getMessage());
	        } catch (IOException e) {
	        	System.out.println("Caught Exception writing .pem file");
	        }
            
            // Add security group and key pair to RunInstancesRequest
            rir.withSecurityGroups(testGroup).withKeyName(testKey);
            
            RunInstancesResult result = ec2.runInstances(rir);
            
            //get instanceId from the result
            List<Instance> resultInstance = result.getReservation().getInstances();
            String createdInstanceId = null;
            for (Instance ins : resultInstance){
            	createdInstanceId = ins.getInstanceId();
            	System.out.println("New instance has been created: "+ins.getInstanceId());
            }
            
            
            /*********************************************
             * 
             *  #7 Create a 'tag' for the new instance.
             *  
             *********************************************/
            System.out.println("#7 Create a 'tag' for the new instance.");
            List<String> resources = new LinkedList<String>();
            List<Tag> tags = new LinkedList<Tag>();
            Tag nameTag = new Tag("Name", "MyFirstInstance");
            
            resources.add(createdInstanceId);
            tags.add(nameTag);
            
            CreateTagsRequest ctr = new CreateTagsRequest(resources, tags);
            ec2.createTags(ctr);
            
            
                        
            /*********************************************
             * 
             *  #8 Stop/Start an Instance
             *  
             *********************************************/
            System.out.println("#8 Stop the Instance");
            List<String> instanceIds = new LinkedList<String>();
            instanceIds.add(createdInstanceId);
            
            //stop
            StopInstancesRequest stopIR = new StopInstancesRequest(instanceIds);
            //ec2.stopInstances(stopIR);
            
            //start
            StartInstancesRequest startIR = new StartInstancesRequest(instanceIds);
            //ec2.startInstances(startIR);
            
            
            /*********************************************
             * 
             *  #9 Terminate an Instance
             *  
             *********************************************/
            System.out.println("#9 Terminate the Instance");
            TerminateInstancesRequest tir = new TerminateInstancesRequest(instanceIds);
            //ec2.terminateInstances(tir);
            
                        
            /*********************************************
             *  
             *  #10 shutdown client object
             *  
             *********************************************/
            ec2.shutdown();
            System.out.println("#10 Successfully Shutdown Client Object");
            
            
            
        } catch (AmazonServiceException ase) {
                System.out.println("Caught Exception: " + ase.getMessage());
                System.out.println("Reponse Status Code: " + ase.getStatusCode());
                System.out.println("Error Code: " + ase.getErrorCode());
                System.out.println("Request ID: " + ase.getRequestId());
        }

        
    }
}

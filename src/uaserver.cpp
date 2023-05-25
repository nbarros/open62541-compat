/* © Copyright Piotr Nikiel, CERN, 2019.  All rights not expressly granted are reserved.
 * uaserver.cpp
 *
 *  Created on: 29 Nov 2019
 *      Author: Piotr Nikiel <piotr@nikiel.info>
 *
 *  This file is part of Quasar.
 *
 *  Quasar is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public Licence as published by
 *  the Free Software Foundation, either version 3 of the Licence.
 *
 *  Quasar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public Licence for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with Quasar.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdexcept>

#include <open62541.h>

#include <uaserver.h>
#include <statuscode.h>
#include <open62541_compat.h>
#include <logit_logger.h>

#include <LogIt.h>

#ifdef HAS_SERVERCONFIG_LOADER
#include <ServerConfig.hxx>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>
#endif // HAS_SERVERCONFIG_LOADER

/*
typedef struct {
    UA_Boolean allowAnonymous;
    size_t usernamePasswordLoginSize;
    UA_UsernamePasswordLogin *usernamePasswordLogin;
} MyAccessControlContext;

#define NANONYMOUS_POLICY "open62541-anonymous-policy"
#define NUSERNAME_POLICY "open62541-username-policy"

const UA_String n_anonymous_policy = UA_STRING_STATIC(NANONYMOUS_POLICY);
const UA_String n_username_policy = UA_STRING_STATIC(NUSERNAME_POLICY);

static UA_StatusCode
activateSession(UA_Server *server, UA_AccessControl *ac,
                        const UA_EndpointDescription *endpointDescription,
                        const UA_ByteString *secureChannelRemoteCertificate,
                        const UA_NodeId *sessionId,
                        const UA_ExtensionObject *userIdentityToken,
                        void **sessionContext) {
  printf("\n\n\nCalling activateSession\n");

    MyAccessControlContext *context = (MyAccessControlContext*)ac->context;

    // The empty token is interpreted as anonymous
    if(userIdentityToken->encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY)
    {
      LOG(Log::INF) << "activateSession : Received an empty token.";
        if(!context->allowAnonymous)
        {
          LOG(Log::ERR) << "activateSession : anonymous tokens are not accepted. Returning invalid.";
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        }
        // No userdata atm
        //TODO: Allow anonymous but add a context that restricts the usage
        *sessionContext = NULL;
        LOG(Log::WRN) << "activateSession : Allowing anonymous token. sessionContext will be empty. Returning good.";

        return UA_STATUSCODE_GOOD;
    }

    // Could the token be decoded?
    if(userIdentityToken->encoding < UA_EXTENSIONOBJECT_DECODED)
    {
      LOG(Log::ERR) << "activateSession : Token could not be decoded. Returning invalid.";
      return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
    }
    // Anonymous login
    if(userIdentityToken->content.decoded.type == &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN])
    {
      LOG(Log::INF) << "activateSession : Received an anonymous token.";
        if(!context->allowAnonymous)
        {
          LOG(Log::ERR) << "activateSession : anonymous tokens are not accepted. Returning invalid.";
           return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        }
        const UA_AnonymousIdentityToken *token = (UA_AnonymousIdentityToken*)
            userIdentityToken->content.decoded.data;

        // Compatibility notice: Siemens OPC Scout v10 provides an empty
        // policyId. This is not compliant. For compatibility, assume that empty
        // policyId == ANONYMOUS_POLICY
        if(token->policyId.data && !UA_String_equal(&token->policyId, &n_anonymous_policy))
        {
          LOG(Log::ERR) << "activateSession : Received an anonymous policy token. Returning invalid.";

            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        }
        // No userdata atm
        *sessionContext = NULL;
        LOG(Log::WRN) << "activateSession : Allowing anonymous policy token. sessionContext will be empty. Returning good.";

        return UA_STATUSCODE_GOOD;
    }

    // Username and password
    if(userIdentityToken->content.decoded.type == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
      printf("\n\nTrying a username/password \n");
      LOG(Log::INF) << "activateSession : Received an username/password token.";


        const UA_UserNameIdentityToken *userToken =
            (UA_UserNameIdentityToken*)userIdentityToken->content.decoded.data;
        LOG(Log::INF) << "activateSession : Decoded data : " << userToken->userName.data
            << ":" << userToken->password.data;

        if(!UA_String_equal(&userToken->policyId, &n_username_policy))
        {
          LOG(Log::ERR) << "activateSession : policyId does not match username policy. Returning invalid.";

            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        }
        // The userToken has been decrypted by the server before forwarding
        // it to the plugin. This information can be used here.
        // if(userToken->encryptionAlgorithm.length > 0) {}

        // Empty username and password
        if(userToken->userName.length == 0 && userToken->password.length == 0)
        {
          LOG(Log::ERR) << "activateSession : user/pwd token with 0 length : (" << userToken->userName.length << ":"<<  userToken->password.length << ")";

            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
        }
        // Try to match username/pw
        UA_Boolean match = false;
        for(size_t i = 0; i < context->usernamePasswordLoginSize; i++) {
            if(UA_String_equal(&userToken->userName, &context->usernamePasswordLogin[i].username) &&
               UA_String_equal(&userToken->password, &context->usernamePasswordLogin[i].password)) {
              printf("\n\nFound a match\n");

              match = true;
                break;
            }
        }
        if(!match)
        {
          LOG(Log::ERR) << "activateSession : Didn't find any user/pwd match.";

          return UA_STATUSCODE_BADUSERACCESSDENIED;

        }

        // For the CTT, recognize whether two sessions are
        UA_ByteString *username = UA_ByteString_new();
        if(username)
            UA_ByteString_copy(&userToken->userName, username);
        printf("Context will have [%s] [%s]\n\n",userToken->userName.data,username->data);
        *sessionContext = username;
        printf("Context has [%s]\n\n",static_cast<UA_ByteString *>(*sessionContext)->data);
        LOG(Log::INF) << "activateSession : all good. sessionContext is set.";

        return UA_STATUSCODE_GOOD;
    }

    // Unsupported token type
    LOG(Log::ERR) << "activateSession : Unsupported token. Returning invalid.";

    return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
}

static UA_Byte
getUserAccessLevel(UA_Server *server, UA_AccessControl *ac,
                           const UA_NodeId *sessionId, void *sessionContext,
                           const UA_NodeId *nodeId, void *nodeContext) {

  UA_String strId;
  UA_String_init(&strId);
  UA_NodeId_print(sessionId, &strId);
  UA_String str_nodeId;
  UA_String_init(&str_nodeId);
  UA_NodeId_print(nodeId, &str_nodeId);

  //printf("Checking permission for session %s and context %p %s\n",strId.data,sessionContext, static_cast<UA_ByteString *>(sessionContext)->data);
  //printf("node %s and context %p \n",str_nodeId.data, nodeContext);

  UA_String *context = static_cast<UA_ByteString *>(sessionContext);
  UA_String  u = UA_String_fromChars("nuno");
  if (UA_String_equal(context,&u ))
  {
    return 0xFF; // permit everything
  }
  else
  {
    // everyone else can only read
    return UA_ACCESSLEVELMASK_READ;
  }
}

static UA_Boolean
allowAddNode(UA_Server *server, UA_AccessControl *ac,
             const UA_NodeId *sessionId, void *sessionContext,
             const UA_AddNodesItem *item) {
    printf("Called allowAddNode\n");
    // nobody can add nodes
    return UA_FALSE; //UA_TRUE;
}

static UA_Boolean
allowAddReference(UA_Server *server, UA_AccessControl *ac,
                  const UA_NodeId *sessionId, void *sessionContext,
                  const UA_AddReferencesItem *item) {
    printf("Called allowAddReference\n");
    return UA_FALSE; //UA_TRUE;
}

static UA_Boolean
allowDeleteNode(UA_Server *server, UA_AccessControl *ac,
                const UA_NodeId *sessionId, void *sessionContext,
                const UA_DeleteNodesItem *item) {
    printf("Called allowDeleteNode\n");
    return UA_FALSE; // Do not allow deletion from client
}

static UA_Boolean
allowDeleteReference(UA_Server *server, UA_AccessControl *ac,
                     const UA_NodeId *sessionId, void *sessionContext,
                     const UA_DeleteReferencesItem *item) {
    printf("Called allowDeleteReference\n");
    return UA_FALSE; //UA_TRUE;
}

static UA_Boolean
getUserExecutableOnObject(UA_Server *server, UA_AccessControl *ac,
                                  const UA_NodeId *sessionId, void *sessionContext,
                                  const UA_NodeId *methodId, void *methodContext,
                                  const UA_NodeId *objectId, void *objectContext) {
  UA_String str_nodeId;
  UA_String_init(&str_nodeId);
  UA_NodeId_print(methodId, &str_nodeId);

  UA_String str_objId;
  UA_String_init(&str_objId);
  UA_NodeId_print(objectId, &str_objId);

  printf("Checking permission for method %s obj %s context %p %s\n",str_nodeId.data,str_objId.data,sessionContext, static_cast<UA_ByteString *>(sessionContext)->data);
  //printf("method %s and context %p \n",str_nodeId.data);
  UA_String *context = static_cast<UA_ByteString *>(sessionContext);
  UA_String  u = UA_String_fromChars("nuno");
  if (UA_String_equal(context,&u ))
  {
    printf("\n\nDeclining execute permissions on object\n\n");
    return false;
  }
  else {
    return true;
  }
}

static UA_Boolean
allowBrowseNode(UA_Server *server, UA_AccessControl *ac,
                        const UA_NodeId *sessionId, void *sessionContext,
                        const UA_NodeId *nodeId, void *nodeContext) {

  // TODO: Find if there is a way of figuring out
  // which nodes are methods, to not even allow them to be browsed by
  UA_String str_nodeId;
  UA_String_init(&str_nodeId);
  UA_NodeId_print(nodeId, &str_nodeId);

  printf("Checking browse permission for nodeId %s session context %p %s node context %p\n",
         str_nodeId.data,
         sessionContext,
         static_cast<UA_ByteString *>(sessionContext)->data,
         nodeContext);

  // -- try to figure out if node is a method
  UA_ServerConfig* config = UA_Server_getConfig(server);
  // from the config we can get the nodeStore
  const UA_Node * node = config->nodestore.getNode(config->nodestore.context,nodeId);

  // release the pointer
  config->nodestore.releaseNode(config->nodestore.context,node);

  ///
  /// Method 2: Check directly the NodeClass
  ///
  UA_NodeClass nclass;
  UA_Server_readNodeClass(server,*nodeId,&nclass);
  // UA_StatusCode UA_Server_readNodeClass(UA_Server *server, const UA_NodeId nodeId,
  //                        UA_NodeClass *outNodeClass)
  UA_QualifiedName nqname;
  UA_Server_readBrowseName(server,*nodeId,&nqname);
  //  UA_Server_readBrowseName(UA_Server *server, const UA_NodeId nodeId,
  //                           UA_QualifiedName *outBrowseName)
  if (nclass == UA_NODECLASS_METHOD)
  {
    printf("\n\n\n Node %s is a method\n\n\n",nqname.name.data);
    return false;
  }
  else
  {
    printf("\n\n\n Node %s is NOT a method\n\n\n",nqname.name.data);

  }
//  UA_Server_readNodeClass(UA_Server *server, const UA_NodeId nodeId,
//                          UA_NodeClass *outNodeClass);
  //UA_String_delete(&str_nodeId);
  return true;



  printf("Checking browse permission for nodeId %s session context %p %s node context %p\n",
         str_nodeId.data,
         sessionContext,
         static_cast<UA_ByteString *>(sessionContext)->data,
         nodeContext);
  //printf("method %s and context %p \n",str_nodeId.data);
  UA_String *context = static_cast<UA_ByteString *>(sessionContext);
  UA_String  u = UA_String_fromChars("nuno");
  if (UA_String_equal(context,&u ))
  {
    return true;
  }
  else {
    printf("\n\nDeclining browse permissions\n\n");
    return false;
  }
}

static UA_Boolean
getUserExecutable(UA_Server *server, UA_AccessControl *ac,
                          const UA_NodeId *sessionId, void *sessionContext,
                          const UA_NodeId *methodId, void *methodContext) {
  printf("\n\nCalled getUserExecutable\n\n");


  UA_String str_nodeId;
  UA_String_init(&str_nodeId);
  UA_NodeId_print(methodId, &str_nodeId);

  printf("Checking permission for method %s and context %p %s\n",str_nodeId.data,sessionContext, static_cast<UA_ByteString *>(sessionContext)->data);
  //printf("method %s and context %p \n",str_nodeId.data);
  UA_String *context = static_cast<UA_ByteString *>(sessionContext);
  UA_String  u = UA_String_fromChars("nuno");
  if (UA_String_equal(context,&u ))
  {
    return true;
  }
  else {
    printf("\n\nDeclining execute permissions\n\n");
    return false;
  }
}
*/
///
///
/// AVOID MESSING AROUND BELOW THIS POINT
///
///

UaServer::UaServer() :
m_server(nullptr),
m_nodeManager(nullptr),
m_runningFlag(nullptr),
m_endpointPortNumber(4841)
{

}



UaServer::~UaServer()
{
    // TODO: what if still running?
}

void UaServer::linkAccessControl(BaseAccessControl *ac)
{
  if (ac != NULL)
  {
    m_accessControl = ac;
  }
}

void UaServer::start()
{
    if (!m_runningFlag)
        throw std::logic_error ("Establish the 'running flag' first");
    m_server = UA_Server_new();
    if (!m_server)
        OPEN62541_COMPAT_LOG_AND_THROW(std::runtime_error, "UA_Server_new failed");
    UA_ServerConfig* config = UA_Server_getConfig(m_server);
    //UA_ServerConfig_setMinimal(config, m_endpointPortNumber, nullptr);
    UA_ServerConfig_setMinimal(config, m_endpointPortNumber, nullptr);


    // an access control class has been linked
    if (m_accessControl)
    {
      m_accessControl->link_callbacks(m_server);
    }
//        UA_UsernamePasswordLogin logins[2] = {
//            {UA_STRING_STATIC("peter"), UA_STRING_STATIC("peter123")},
//            {UA_STRING_STATIC("nuno"), UA_STRING_STATIC("nuno123")}
//        };
//
    /* Disable anonymous logins, enable two user/password logins */
//    config->accessControl.clear(&config->accessControl);
//    UA_StatusCode retval = UA_AccessControl_default(config, false,
//               &config->securityPolicies[config->securityPoliciesSize-1].policyUri, 2, logins);
//    if (retval != UA_STATUSCODE_GOOD)
//    {
//      LOG(Log::ERR) <<
//      "UA_AccessControl_default returned: " << UaStatus(retval).toString().toUtf8();
//    }
//    else
//    {
//      LOG(Log::INF) <<
//      "UA_AccessControl_default returned: " << UaStatus(retval).toString().toUtf8();
//
//    }
//    config->accessControl.activateSession = activateSession;
//    config->accessControl.getUserAccessLevel = getUserAccessLevel;
//    config->accessControl.allowAddNode = allowAddNode;
//    config->accessControl.allowAddReference = allowAddReference;
//    config->accessControl.allowDeleteNode = allowDeleteNode;
//    config->accessControl.allowDeleteReference = allowDeleteReference;
//    config->accessControl.getUserExecutableOnObject = getUserExecutableOnObject;
//    config->accessControl.allowBrowseNode = allowBrowseNode;
//    config->accessControl.getUserExecutable = getUserExecutable;




	// use LogIt logger for open62541
    initializeOpen62541LogIt();
    config->logger = theLogItLogger;

    m_nodeManager->linkServer(m_server);
    m_nodeManager->afterStartUp();

    UA_StatusCode status = UA_Server_run_startup(m_server);
    if (status != UA_STATUSCODE_GOOD)
        throw std::runtime_error("UA_Server_run_startup returned not-good, server can't start. Error was:"+
                UaStatus(status).toString().toUtf8());
    else
        LOG(Log::INF) <<
        "UA_Server_run_startup returned: " << UaStatus(status).toString().toUtf8() << ", continuing.";
    m_open62541_server_thread = std::thread ( &UaServer::runThread, this );
}

void UaServer::runThread()
{
    while (*m_runningFlag)
    {
        UA_Server_run_iterate(m_server, true);
    }
    UA_StatusCode status = UA_Server_run_shutdown(m_server);
    if (status != UA_STATUSCODE_GOOD)
    {
        LOG(Log::ERR) << "UA_Server_run_shutdown returned not-good. Error was:" << UaStatus(status).toString().toUtf8();
    }
    else
        LOG(Log::INF) << "UA_Server_run_shutdown returned: " << UaStatus(status).toString().toUtf8();
}

void UaServer::addNodeManager(NodeManagerBase* pNodeManager)
{
    if (!m_nodeManager)
        m_nodeManager = pNodeManager;
    else
        OPEN62541_COMPAT_LOG_AND_THROW(std::logic_error, "Sorry, only 1 NodeManager is supported.");
}

void UaServer::linkRunningFlag (volatile OpcUa_Boolean* flag)
{
    m_runningFlag = flag;
}

void UaServer::setServerConfig(
        const UaString& configurationFile,
        const UaString& applicationPath)
{
#ifndef HAS_SERVERCONFIG_LOADER
    LOG(Log::INF) << "Note: you built open62541-compat without configuration loading (option SERVERCONFIG_LOADER). So loading of ServerConfig.xml is not supported. Assuming hardcoded server settings (endpoint's port, etc.)";
    //! With open62541 1.0, it is the UA_Server that holds the config.
#else // HAS_SERVERCONFIG_LOADER is defined, means the user wants the option
    std::unique_ptr< ::ServerConfig::OpcServerConfig > serverConfig;
     try
     {
         serverConfig = ServerConfig::OpcServerConfig_ (configurationFile.toUtf8());
     }
     catch (xsd::cxx::tree::parsing<char> &exception)
     {
         LOG(Log::ERR) << "ServerConfig loader: failed when trying to open the file, with general error message: " << exception.what();
         for( const xsd::cxx::tree::error<char> &error : exception.diagnostics() )
         {
             LOG(Log::ERR) << "ServerConfig: Problem at " << error.id() << ":" << error.line() << ": " << error.message();
         }
         OPEN62541_COMPAT_LOG_AND_THROW(std::runtime_error, "ServerConfig: failed to load ServerConfig. The exact problem description should have been logged.");

     }
     // minimum one endpoint is guaranteed by the XSD, but in case user declared more, refuse to continue
     // TODO: implement multiple endpoints
     const ServerConfig::UaServerConfig& uaServerConfig = serverConfig->UaServerConfig();
     if (uaServerConfig.UaEndpoint().size() > 1)
     {
         OPEN62541_COMPAT_LOG_AND_THROW(std::runtime_error, "No support for multiple UaEndpoints yet, simplify your ServerConfig.xml");
     }
     boost::regex endpointUrlRegex("^opc\\.tcp:\\/\\/\\[NodeName\\]:(?<port>\\d+)$");
     boost::smatch matchResults;
     std::string endpointUrl (uaServerConfig.UaEndpoint()[0].Url() );
     bool matched = boost::regex_match( endpointUrl, matchResults, endpointUrlRegex );
     if (!matched)
         OPEN62541_COMPAT_LOG_AND_THROW(std::runtime_error, "Can't parse UaEndpoint/Url, note it should look like 'opc.tcp://[NodeName]:4841' perhaps with different port number, yours is '"+endpointUrl+"'");
     unsigned int endpointUrlPort = boost::lexical_cast<unsigned int>(matchResults["port"]);
     LOG(Log::INF) << "From your [" << configurationFile.toUtf8() << "] loaded endpoint port number: " << endpointUrlPort;
     m_endpointPortNumber = endpointUrlPort;
#endif
}

void UaServer::stop ()
{
	if (m_open62541_server_thread.joinable()) // if start() was never called, or server failed to start, the thread is not joinable...
		m_open62541_server_thread.join();
    delete m_nodeManager;
    m_nodeManager = nullptr;
    UA_Server_delete(m_server);
    m_server = nullptr;
}

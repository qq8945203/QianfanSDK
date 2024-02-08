/*
 * 千帆SDK
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 1.0.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.baidubce.sdc.sdk.api;

import com.baidubce.sdc.sdk.ApiCallback;
import com.baidubce.sdc.sdk.ApiClient;
import com.baidubce.sdc.sdk.ApiException;
import com.baidubce.sdc.sdk.ApiResponse;
import com.baidubce.sdc.sdk.Configuration;
import com.baidubce.sdc.sdk.Pair;

import com.google.gson.reflect.TypeToken;

import java.io.IOException;


import com.baidubce.sdc.sdk.model.qianfan.ChatLlm;
import com.baidubce.sdc.sdk.model.qianfan.ChatRequest;
import com.baidubce.sdc.sdk.model.qianfan.ChatResponse;
import com.baidubce.sdc.sdk.model.qianfan.CompletionLlm;
import com.baidubce.sdc.sdk.model.qianfan.CompletionRequest;
import com.baidubce.sdc.sdk.model.qianfan.CompletionResponse;
import com.baidubce.sdc.sdk.model.qianfan.EmbeddingLlm;
import com.baidubce.sdc.sdk.model.qianfan.EmbeddingRequest;
import com.baidubce.sdc.sdk.model.qianfan.EmbeddingResponse;
import com.baidubce.sdc.sdk.model.qianfan.ImageLlm;
import com.baidubce.sdc.sdk.model.qianfan.ImageRequest;
import com.baidubce.sdc.sdk.model.qianfan.ImageResponse;
import com.baidubce.sdc.sdk.model.qianfan.PluginRequest;
import com.baidubce.sdc.sdk.model.qianfan.PluginResponse;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class QianfanApi {
    private ApiClient localVarApiClient;
    private String localCustomBaseUrl;

    public QianfanApi() {
        this(Configuration.getDefaultApiClient());
    }

    public QianfanApi(ApiClient apiClient) {
        this.localVarApiClient = apiClient;
    }

    public ApiClient getApiClient() {
        return localVarApiClient;
    }

    public void setApiClient(ApiClient apiClient) {
        this.localVarApiClient = apiClient;
    }

    public String getCustomBaseUrl() {
        return localCustomBaseUrl;
    }

    public void setCustomBaseUrl(String customBaseUrl) {
        this.localCustomBaseUrl = customBaseUrl;
    }

    /**
     * Build call for chat
     * @param llm  (required)
     * @param chatRequest  (required)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call chatCall(ChatLlm llm, ChatRequest chatRequest, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        
        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        }

        Object localVarPostBody = chatRequest;

        // create path and map variables
        String localVarPath = "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/{llm}"
            .replace("{" + "llm" + "}", localVarApiClient.escapeString(llm.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "IamAuth", "OAuth" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call chatValidateBeforeCall(ChatLlm llm, ChatRequest chatRequest, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'llm' is set
        if (llm == null) {
            throw new ApiException("Missing the required parameter 'llm' when calling chat(Async)");
        }

        // verify the required parameter 'chatRequest' is set
        if (chatRequest == null) {
            throw new ApiException("Missing the required parameter 'chatRequest' when calling chat(Async)");
        }

        return chatCall(llm, chatRequest, _callback);

    }

    /**
     * 调用对话类大模型
     * 
     * @param llm  (required)
     * @param chatRequest  (required)
     * @return ChatResponse
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public ChatResponse chat(ChatLlm llm, ChatRequest chatRequest) throws ApiException {
        if (Boolean.TRUE.equals(chatRequest.getStream())){
            throw new IllegalArgumentException("Stream call please use chatAsync method.(流式调用请使用chatAsync方法)");
        }
        ApiResponse<ChatResponse> localVarResp = chatWithHttpInfo(llm, chatRequest);
        return localVarResp.getData();
    }

    /**
     * 调用对话类大模型
     * 
     * @param llm  (required)
     * @param chatRequest  (required)
     * @return ApiResponse&lt;ChatResponse&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<ChatResponse> chatWithHttpInfo(ChatLlm llm, ChatRequest chatRequest) throws ApiException {
        okhttp3.Call localVarCall = chatValidateBeforeCall(llm, chatRequest, null);
        Type localVarReturnType = new TypeToken<ChatResponse>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * 调用对话类大模型 (asynchronously)
     * 
     * @param llm  (required)
     * @param chatRequest  (required)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call chatAsync(ChatLlm llm, ChatRequest chatRequest, final ApiCallback<ChatResponse> _callback) throws ApiException {

        okhttp3.Call localVarCall = chatValidateBeforeCall(llm, chatRequest, _callback);
        Type localVarReturnType = new TypeToken<ChatResponse>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for completion
     * @param llm  (required)
     * @param completionRequest  (required)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call completionCall(CompletionLlm llm, CompletionRequest completionRequest, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        
        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        }

        Object localVarPostBody = completionRequest;

        // create path and map variables
        String localVarPath = "/rpc/2.0/ai_custom/v1/wenxinworkshop/completions/{llm}"
            .replace("{" + "llm" + "}", localVarApiClient.escapeString(llm.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "IamAuth", "OAuth" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call completionValidateBeforeCall(CompletionLlm llm, CompletionRequest completionRequest, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'llm' is set
        if (llm == null) {
            throw new ApiException("Missing the required parameter 'llm' when calling completion(Async)");
        }

        // verify the required parameter 'completionRequest' is set
        if (completionRequest == null) {
            throw new ApiException("Missing the required parameter 'completionRequest' when calling completion(Async)");
        }

        return completionCall(llm, completionRequest, _callback);

    }

    /**
     * 调用续写类大模型
     * 
     * @param llm  (required)
     * @param completionRequest  (required)
     * @return CompletionResponse
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public CompletionResponse completion(CompletionLlm llm, CompletionRequest completionRequest) throws ApiException {
        if (Boolean.TRUE.equals(completionRequest.getStream())){
            throw new IllegalArgumentException("Stream call please use completionAsync method.(流式调用请使用completionAsync方法)");
        }
        ApiResponse<CompletionResponse> localVarResp = completionWithHttpInfo(llm, completionRequest);
        return localVarResp.getData();
    }

    /**
     * 调用续写类大模型
     * 
     * @param llm  (required)
     * @param completionRequest  (required)
     * @return ApiResponse&lt;CompletionResponse&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<CompletionResponse> completionWithHttpInfo(CompletionLlm llm, CompletionRequest completionRequest) throws ApiException {
        okhttp3.Call localVarCall = completionValidateBeforeCall(llm, completionRequest, null);
        Type localVarReturnType = new TypeToken<CompletionResponse>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * 调用续写类大模型 (asynchronously)
     * 
     * @param llm  (required)
     * @param completionRequest  (required)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call completionAsync(CompletionLlm llm, CompletionRequest completionRequest, final ApiCallback<CompletionResponse> _callback) throws ApiException {

        okhttp3.Call localVarCall = completionValidateBeforeCall(llm, completionRequest, _callback);
        Type localVarReturnType = new TypeToken<CompletionResponse>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for embedding
     * @param llm  (required)
     * @param embeddingRequest  (required)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call embeddingCall(EmbeddingLlm llm, EmbeddingRequest embeddingRequest, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        
        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        }

        Object localVarPostBody = embeddingRequest;

        // create path and map variables
        String localVarPath = "/rpc/2.0/ai_custom/v1/wenxinworkshop/embeddings/{llm}"
            .replace("{" + "llm" + "}", localVarApiClient.escapeString(llm.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "IamAuth", "OAuth" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call embeddingValidateBeforeCall(EmbeddingLlm llm, EmbeddingRequest embeddingRequest, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'llm' is set
        if (llm == null) {
            throw new ApiException("Missing the required parameter 'llm' when calling embedding(Async)");
        }

        // verify the required parameter 'embeddingRequest' is set
        if (embeddingRequest == null) {
            throw new ApiException("Missing the required parameter 'embeddingRequest' when calling embedding(Async)");
        }

        return embeddingCall(llm, embeddingRequest, _callback);

    }

    /**
     * 调用支持向量计算类的大模型接口
     * 
     * @param llm  (required)
     * @param embeddingRequest  (required)
     * @return EmbeddingResponse
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public EmbeddingResponse embedding(EmbeddingLlm llm, EmbeddingRequest embeddingRequest) throws ApiException {
        
        ApiResponse<EmbeddingResponse> localVarResp = embeddingWithHttpInfo(llm, embeddingRequest);
        return localVarResp.getData();
    }

    /**
     * 调用支持向量计算类的大模型接口
     * 
     * @param llm  (required)
     * @param embeddingRequest  (required)
     * @return ApiResponse&lt;EmbeddingResponse&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<EmbeddingResponse> embeddingWithHttpInfo(EmbeddingLlm llm, EmbeddingRequest embeddingRequest) throws ApiException {
        okhttp3.Call localVarCall = embeddingValidateBeforeCall(llm, embeddingRequest, null);
        Type localVarReturnType = new TypeToken<EmbeddingResponse>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * 调用支持向量计算类的大模型接口 (asynchronously)
     * 
     * @param llm  (required)
     * @param embeddingRequest  (required)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call embeddingAsync(EmbeddingLlm llm, EmbeddingRequest embeddingRequest, final ApiCallback<EmbeddingResponse> _callback) throws ApiException {

        okhttp3.Call localVarCall = embeddingValidateBeforeCall(llm, embeddingRequest, _callback);
        Type localVarReturnType = new TypeToken<EmbeddingResponse>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for plugin
     * @param serverPath  (required)
     * @param pluginRequest  (required)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call pluginCall(String serverPath, PluginRequest pluginRequest, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        
        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        }

        Object localVarPostBody = pluginRequest;

        // create path and map variables
        String localVarPath = "/rpc/2.0/ai_custom/v1/wenxinworkshop/plugin/{serverPath}/"
            .replace("{" + "serverPath" + "}", localVarApiClient.escapeString(serverPath.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "IamAuth", "OAuth" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call pluginValidateBeforeCall(String serverPath, PluginRequest pluginRequest, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'serverPath' is set
        if (serverPath == null) {
            throw new ApiException("Missing the required parameter 'serverPath' when calling plugin(Async)");
        }

        // verify the required parameter 'pluginRequest' is set
        if (pluginRequest == null) {
            throw new ApiException("Missing the required parameter 'pluginRequest' when calling plugin(Async)");
        }

        return pluginCall(serverPath, pluginRequest, _callback);

    }

    /**
     * 调用插件接口
     * 
     * @param serverPath  (required)
     * @param pluginRequest  (required)
     * @return PluginResponse
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public PluginResponse plugin(String serverPath, PluginRequest pluginRequest) throws ApiException {
        if (Boolean.TRUE.equals(pluginRequest.getStream())){
            throw new IllegalArgumentException("Stream call please use pluginAsync method.(流式调用请使用pluginAsync方法)");
        }
        ApiResponse<PluginResponse> localVarResp = pluginWithHttpInfo(serverPath, pluginRequest);
        return localVarResp.getData();
    }

    /**
     * 调用插件接口
     * 
     * @param serverPath  (required)
     * @param pluginRequest  (required)
     * @return ApiResponse&lt;PluginResponse&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<PluginResponse> pluginWithHttpInfo(String serverPath, PluginRequest pluginRequest) throws ApiException {
        okhttp3.Call localVarCall = pluginValidateBeforeCall(serverPath, pluginRequest, null);
        Type localVarReturnType = new TypeToken<PluginResponse>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * 调用插件接口 (asynchronously)
     * 
     * @param serverPath  (required)
     * @param pluginRequest  (required)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call pluginAsync(String serverPath, PluginRequest pluginRequest, final ApiCallback<PluginResponse> _callback) throws ApiException {

        okhttp3.Call localVarCall = pluginValidateBeforeCall(serverPath, pluginRequest, _callback);
        Type localVarReturnType = new TypeToken<PluginResponse>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for text2image
     * @param llm  (required)
     * @param imageRequest  (required)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call text2imageCall(ImageLlm llm, ImageRequest imageRequest, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        
        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        }

        Object localVarPostBody = imageRequest;

        // create path and map variables
        String localVarPath = "/rpc/2.0/ai_custom/v1/wenxinworkshop/text2image/{llm}"
            .replace("{" + "llm" + "}", localVarApiClient.escapeString(llm.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "IamAuth", "OAuth" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call text2imageValidateBeforeCall(ImageLlm llm, ImageRequest imageRequest, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'llm' is set
        if (llm == null) {
            throw new ApiException("Missing the required parameter 'llm' when calling text2image(Async)");
        }

        // verify the required parameter 'imageRequest' is set
        if (imageRequest == null) {
            throw new ApiException("Missing the required parameter 'imageRequest' when calling text2image(Async)");
        }

        return text2imageCall(llm, imageRequest, _callback);

    }

    /**
     * 调用文生图类大模型
     * 
     * @param llm  (required)
     * @param imageRequest  (required)
     * @return ImageResponse
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public ImageResponse text2image(ImageLlm llm, ImageRequest imageRequest) throws ApiException {
        
        ApiResponse<ImageResponse> localVarResp = text2imageWithHttpInfo(llm, imageRequest);
        return localVarResp.getData();
    }

    /**
     * 调用文生图类大模型
     * 
     * @param llm  (required)
     * @param imageRequest  (required)
     * @return ApiResponse&lt;ImageResponse&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<ImageResponse> text2imageWithHttpInfo(ImageLlm llm, ImageRequest imageRequest) throws ApiException {
        okhttp3.Call localVarCall = text2imageValidateBeforeCall(llm, imageRequest, null);
        Type localVarReturnType = new TypeToken<ImageResponse>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * 调用文生图类大模型 (asynchronously)
     * 
     * @param llm  (required)
     * @param imageRequest  (required)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> 成功 </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call text2imageAsync(ImageLlm llm, ImageRequest imageRequest, final ApiCallback<ImageResponse> _callback) throws ApiException {

        okhttp3.Call localVarCall = text2imageValidateBeforeCall(llm, imageRequest, _callback);
        Type localVarReturnType = new TypeToken<ImageResponse>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
}
import IRESTClient, { ErrorResponseHandler, ResponseHandler } from "./IRESTClient";
import ClientResponse from "./ClientResponse";
/**
 * @author Brett P
 * @author Tyler Scott
 * @author TJ Peden
 */
export default class DefaultRESTClient<RT, ERT> implements IRESTClient<RT, ERT> {
    host: string;
    body: unknown;
    headers: Record<string, string>;
    method: string;
    parameters: Record<string, string>;
    uri: string;
    credentials: RequestCredentials;
    responseHandler: ResponseHandler<RT>;
    errorResponseHandler: ErrorResponseHandler<ERT>;
    constructor(host: string);
    /**
     * Sets the authorization header using a key
     *
     * @param {string} key The value of the authorization header.
     * @returns {DefaultRESTClient}
     */
    withAuthorization(key: string): DefaultRESTClient<RT, ERT>;
    /**
     * Adds a segment to the request uri
     */
    withUriSegment(segment: string | number): DefaultRESTClient<RT, ERT>;
    /**
     * Get the full url + parameter list
     */
    getFullUrl(): string;
    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as form data.
     */
    withFormData(body: object): DefaultRESTClient<RT, ERT>;
    /**
     * Adds a header to the request.
     *
     * @param key The name of the header.
     * @param value The value of the header.
     */
    withHeader(key: string, value: string): DefaultRESTClient<RT, ERT>;
    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as JSON.
     */
    withJSONBody(body: object): DefaultRESTClient<RT, ERT>;
    /**
     * Sets the http method for the request
     */
    withMethod(method: string): DefaultRESTClient<RT, ERT>;
    /**
     * Sets the uri of the request
     */
    withUri(uri: string): DefaultRESTClient<RT, ERT>;
    /**
     * Adds parameters to the request.
     *
     * @param name The name of the parameter.
     * @param value The value of the parameter, may be a string, object or number.
     */
    withParameter(name: string, value: any): DefaultRESTClient<RT, ERT>;
    /**
     * Sets request's credentials.
     *
     * @param value A string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL.
     */
    withCredentials(value: RequestCredentials): DefaultRESTClient<RT, ERT>;
    withResponseHandler(handler: ResponseHandler<RT>): DefaultRESTClient<RT, ERT>;
    withErrorResponseHandler(handler: ErrorResponseHandler<ERT>): DefaultRESTClient<RT, ERT>;
    /**
     * Run the request and return a promise. This promise will resolve if the request is successful
     * and reject otherwise.
     */
    go(): Promise<ClientResponse<RT>>;
    private getQueryString;
    private static emptyResponseHandler;
}

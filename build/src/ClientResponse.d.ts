export default class ClientResponse<T> {
    statusCode: number;
    response: T;
    exception: Error;
    wasSuccessful(): boolean;
}

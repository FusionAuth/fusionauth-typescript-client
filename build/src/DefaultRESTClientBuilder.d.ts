import IRESTClient from "./IRESTClient";
import IRESTClientBuilder from "./IRESTClientBuilder";
export default class DefaultRESTClientBuilder implements IRESTClientBuilder {
    build<RT, ERT>(host: string): IRESTClient<RT, ERT>;
}

import IRESTClient from "./IRESTClient";
export default interface IRESTClientBuilder {
    build<RT, ERT>(host: string): IRESTClient<RT, ERT>;
}

import { Type } from "@nestjs/common";
import { IGrantedInfoProvider } from "src/services";

export class GrantedModuleOptions {
    apply?: boolean;
    infoProvider?: IGrantedInfoProvider;
}
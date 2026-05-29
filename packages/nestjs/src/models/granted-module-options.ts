import { IGrantedInfoProvider } from '../services';

export class GrantedModuleOptions {
  apply?: boolean;
  infoProvider?: IGrantedInfoProvider;
}

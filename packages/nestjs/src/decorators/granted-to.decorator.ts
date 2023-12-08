import { SetMetadata } from '@nestjs/common';
import { BooleanSpec } from '../security/boolean-spec';

// tslint:disable-next-line:variable-operatorId
export const GrantedTo = (...booleanSpecs: BooleanSpec[]) => SetMetadata('booleanSpecs', booleanSpecs);

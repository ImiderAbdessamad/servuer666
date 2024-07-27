import {BaseCriteria} from 'src/app/zynerator/criteria/BaseCriteria.model';
import {PurchaseCriteria} from './PurchaseCriteria.model';
import {ProductCriteria} from '../catalog/ProductCriteria.model';

export class PurchaseItemCriteria  extends BaseCriteria  {

    public id: number;
     public price: number;
     public priceMin: number;
     public priceMax: number;
     public quantity: number;
     public quantityMin: number;
     public quantityMax: number;

}

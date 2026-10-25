export function deliveryAwait<T>(promise:Promise<T>,signal:AbortSignal):Promise<T>{
 if(signal.aborted)return Promise.reject(new Error('EVENT_DELIVERY_ABORTED'));
 return new Promise((resolve,reject)=>{
  const stop=()=>reject(new Error('EVENT_DELIVERY_ABORTED'));signal.addEventListener('abort',stop,{once:true});
  promise.then(value=>{signal.removeEventListener('abort',stop);if(signal.aborted)reject(new Error('EVENT_DELIVERY_ABORTED'));else resolve(value);},error=>{signal.removeEventListener('abort',stop);reject(error);});
 });
}

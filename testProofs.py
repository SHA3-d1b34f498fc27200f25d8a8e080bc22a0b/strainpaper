import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz, powmod,divm
from GM import generate_keys, encrypt_gm,getNextRandom,decrypt_gm
from proofs import gm_eval_honest, compare_leq_honest, proof_dlog_eq, \
    verify_dlog_eq, proof_eval, verify_eval,encrypt_gm_coin,hash_flat
import time,pdb,numpy,sys
from testGM import test_gm_bit_and
import random as rnd
import sys

def rand32(n):
    a = list()
    for i in xrange(32):
        a.append(getNextRandom(n))

    return a

def strain_main():
    keys1 = generate_keys()    
    n1 = keys1['pub']
    p1, q1 = keys1['priv']
    
    keys2 = generate_keys()
    n2 = keys2['pub']
    p2, q2 = keys2['priv']

    v1 = mpz(random.randint(0, 2**31-1))
    R1 = rand32(n1)
    C1 = encrypt_gm_coin(v1, n1,R1)

    v2 = mpz(random.randint(0, 2**31-1))
    R2 = rand32(n2)
    C2 = encrypt_gm_coin(v2, n2,R2)

    R12 = rand32(n2)
    timings = list()
    print "Encryption timings...",
    sys.stdout.flush()
    for i in xrange(10):
        startTime = time.time()
        C12 = encrypt_gm_coin(v1, n2, R12)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = 100*numpy.std(timings)/avg
    print "Avg:",str(round(1000*avg,3))+"ms","rel. std. dev.:",str(round(rstd,2)),"%"

    privatekey = keys2['priv']
    timings = list()
    print "Decryption timings...",
    sys.stdout.flush()
    for i in xrange(10):
        startTime = time.time()
        decrypt_gm(C12, privatekey)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = 100*numpy.std(timings)/avg
    print "Avg:",str(round(1000*avg,2))+"ms","rel. std. dev.:",str(round(rstd,2)),"%"

        
    RAND1 = list()
    RAND2 = list()
    RAND3 = list()
    RAND4 = list()
    for i in xrange(32):
        x = list()
        y = list()
        x2 = list()
        y2 = list()
        for j in xrange(128):
            x.append(getNextRandom(n2) )
            y.append(getNextRandom(n2) )
            x2.append(getNextRandom(n2) )
            y2.append(getNextRandom(n2) )
        
        RAND1.append(x)
        RAND2.append(y)
        RAND3.append(x2)
        RAND4.append(y2)

    print "Eval computation timings...",
    sys.stdout.flush()
    timings = list()
    for i in xrange(10):
        startTime = time.time()
        eval_res = gm_eval_honest(v1, C12, C2, n2, RAND1, RAND2,RAND3,RAND4)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = numpy.std(timings)/avg
    print "avg:",str(round(avg,2))+"s,","rel.std.dev.", str(round(rstd,2))+"%"
    assert( (v2 <= v1) == compare_leq_honest(eval_res, keys2['priv']) )

    print "Proof_Eval computation timings...",
    sys.stdout.flush()                                                      
    timings = list()
    for i in xrange(10):
        startTime = time.time()
        P_eval, plaintext_and_coins = proof_eval(C1, C2, C12, v1, n1, n2,R1,R12,40)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = numpy.std(timings)/avg
    print "avg:",str(round(1000*avg,2))+"ms,", "rel.std.dev.:",str(round(rstd,2))+"%"

    print "Verify_Eval computation timings...",
    sys.stdout.flush()
    timings = list()
    for  i  in xrange(10):
        startTime = time.time()
        eval_res = verify_eval(P_eval, plaintext_and_coins, n1, n2,40)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = numpy.std(timings)/avg
    print "avg:",str(round(1000*avg,2))+"ms,", "rel.std.dev.:",str(round(rstd,2))+"%"

    
def test_gm_eval_honest(iters=1):
    print "test_gm_eval_honest"
    keys = generate_keys()    
    n = keys['pub']
    priv_key = keys['priv']  
    
    for i in range(iters):
        
        v1 = mpz(random.randint(0, 2**31-1))
        v2 = mpz(random.randint(0, 2**31-1))
        print 'i=',i,'v1=', v1, 'v2=',v2
        cipher2 = encrypt_gm(v2, n)

        startTime = time.time()
        eval_res = gm_eval_honest(v1, cipher2, n)
        print "Eval elapsed:"+str(time.time()-startTime)
        
        assert( (v2 <= v1) == compare_leq_honest(eval_res, priv_key) )
        
    print "test_gm_eval_honest pass"
    
def test_proof_eval(iters=1):
    print "test_proof_eval"
    keys1 = generate_keys()    
    n1 = keys1['pub']
    p1, q1 = keys1['priv']
    
    keys2 = generate_keys()
    n2 = keys2['pub']
    p2, q2 = keys2['priv']
    
    print "test honest model"
    for i in range(iters):
        print "i =", i
        v1 = mpz(random.randint(0, 2**31-1))
        startTime = time.time()
        C1 = encrypt_gm(v1, n1)
        print "Enc elapsed:"+str(time.time()-startTime)

        v2 = mpz(random.randint(0, 2**31-1))
        C2 = encrypt_gm(v2, n2)
    
        C12 = encrypt_gm(v1, n2)

        startTime = time.time()
        P_eval, plaintext_and_coins = proof_eval(C1, C2, C12, v1, n1, n2)
        print "p_eval elapsed:"+str(time.time()-startTime)

        startTime = time.time()
        eval_res = verify_eval(P_eval, plaintext_and_coins, n1, n2)
        print "verify eval:"+str(time.time()-startTime)
        
        assert(eval_res != None)
        assert( (v2 <= v1) == compare_leq_honest(eval_res, (p2, q2)) )
        
        # flip one bit
        # Doesn't work...
        """
        v1x = v1 ^ (1 << random.randint(0, 30))
        C12x = encrypt_gm(v1x, n2)
        
        P_eval_x1, plaintext_and_coins_x1 = proof_eval(C1, C2, C12, v1x, n1, n2)
        P_eval_x2, plaintext_and_coins_x2 = proof_eval(C1, C2, C12x, v1, n1, n2)
        P_eval_x3, plaintext_and_coins_x3 = proof_eval(C1, C2, C12x, v1x, n1, n2)
        assert( verify_eval(P_eval_x1, plaintext_and_coins_x1, n1, n2) == None )
        assert( verify_eval(P_eval_x2, plaintext_and_coins_x2, n1, n2) == None )
        assert( verify_eval(P_eval_x3, plaintext_and_coins_x3, n1, n2) == None )
        """
    # end for       
    print "test_proof_eval pass"
# end test_proof_eval


def test_dlog_eq():
    #print "test_dlog_eq:"
    keys = generate_keys()    
    n = keys['pub']
    z = n - 1
    p, q = keys['priv']
    
    r = random.randint(0, int((p-1)*(q-1)))
    y = random.randint(0, int(n-1))

    Y = powmod(y, r, n)
    Z = powmod(z, r, n)

    print "Proof DLOG computation timings...",
    sys.stdout.flush()
    timings = list()
    for i in xrange(10):
        startTime = time.time()
        P_dlog = proof_dlog_eq(r, y, n, 40)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = numpy.std(timings)/avg
    print "avg:",str(round(1000*avg,2))+"ms,", "rel.std.dev.:",str(round(rstd,2))+"%"

    print "Verify DLOG computation timings...",
    sys.stdout.flush()
    timings = list()
    for i in xrange(10):
        startTime = time.time()
        verify_dlog_eq(n, y, Y, Z, P_dlog, 40)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = numpy.std(timings)/avg
    print "avg:",str(round(1000*avg,2))+"ms,", "rel.std.dev.:",str(round(rstd,2))+"%"
    
    assert(verify_dlog_eq(n, y, Y, Z, P_dlog, 40))

#    P_dlog[random.randint(0, len(P_dlog)-1)][random.randint(0,2)] += \
#        random.choice([-1, 1])

#    assert(not verify_dlog_eq(n, y, Y, Z, P_dlog)) 
        
    #print "test_dlog_eq pass"


def test_shuffle_verify():
    keys1 = generate_keys()    
    n1 = keys1['pub']
    p1, q1 = keys1['priv']
    
    keys2 = generate_keys()
    n2 = keys2['pub']
    p2, q2 = keys2['priv']

    v1 = mpz(random.randint(0, 2**31-1))
    R1 = rand32(n1)
    C1 = encrypt_gm_coin(v1, n1,R1)

    v2 = mpz(random.randint(0, 2**31-1))
    R2 = rand32(n2)
    C2 = encrypt_gm_coin(v2, n2,R2)

    R12 = rand32(n2)
    C12 = encrypt_gm_coin(v1, n2, R12)
    
    RAND1 = list()
    RAND2 = list()
    RAND3 = list()
    RAND4 = list()
    for i in xrange(32):
        x = list()
        y = list()
        x2 = list()
        y2 = list()
        for j in xrange(128):
            x.append(getNextRandom(n2) )
            y.append(getNextRandom(n2) )
            x2.append(getNextRandom(n2) )
            y2.append(getNextRandom(n2) )
        
        RAND1.append(x)
        RAND2.append(y)
        RAND3.append(x2)
        RAND4.append(y2)

    res = gm_eval_honest(v1, C12, C2, n2, RAND1, RAND2,RAND3,RAND4)    
    assert(res != None)
    assert( (v2 <= v1) == compare_leq_honest(res, (p2, q2)) )
    
    proof = compute_proof_shuffle(res,n2)
    
    timings = list()
    print "VerifyShuffle timings...",
    sys.stdout.flush()
    for i in xrange(10):
        startTime = time.time()
        success = verify_shuffle(proof,n2,res)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = 100*numpy.std(timings)/avg
    print "Avg:",str(round(1000*avg,3))+"ms","rel. std. dev.:",str(round(rstd,2)),"%"   

def verify_shuffle(proof,n2,res):    
    hash_input = proof[0]

    h = hash_flat(hash_input)
    bitstring = format(int(h,16),'0256b')
    
    AEpermutation = hash_input[0]
    AM_permutations = dict()
    ME_permutations = dict()

    for i in xrange(40):
        AM_permutations[i], ME_permutations[i] = hash_input[i+1]

    success = True
    
    for i in xrange(40):
        if (bitstring[i] == "0"):
            #open A-M permutation
            AMpermutation_description, AMreencrypt_factors = proof[i+1]
            for j in xrange(len(AMpermutation_description)):
                for k in xrange(40):
                    LHS = ((AM_permutations[i])[AMpermutation_description[j]])[k]
                    r = AMreencrypt_factors[j][k]
                    rsquare = powmod(r,2,n2)
                    RHS = (rsquare * (res[j])[k]) % n2
                    if LHS != RHS:
                        success = False
        else:
            #open M-E permutation
            MEpermutation_description, MEreencrypt_factors = proof[i+1]
            for j in xrange(len(MEpermutation_description)):
                for k in xrange(40):
                    LHS = AEpermutation[MEpermutation_description[j]][k]
                    r = MEreencrypt_factors[j][k]
                    rsquare = powmod(r,2,n2)
                    RHS = (rsquare * ME_permutations[i][j][k]) % n2
                    if LHS != RHS:
                        success = False
            
    return success
    

def test_proof_shuffle():
    keys1 = generate_keys()    
    n1 = keys1['pub']
    p1, q1 = keys1['priv']
    
    keys2 = generate_keys()
    n2 = keys2['pub']
    p2, q2 = keys2['priv']

    v1 = mpz(random.randint(0, 2**31-1))
    R1 = rand32(n1)
    C1 = encrypt_gm_coin(v1, n1,R1)

    v2 = mpz(random.randint(0, 2**31-1))
    R2 = rand32(n2)
    C2 = encrypt_gm_coin(v2, n2,R2)

    R12 = rand32(n2)
    C12 = encrypt_gm_coin(v1, n2, R12)
    
    RAND1 = list()
    RAND2 = list()
    RAND3 = list()
    RAND4 = list()
    for i in xrange(32):
        x = list()
        y = list()
        x2 = list()
        y2 = list()
        for j in xrange(128):
            x.append(getNextRandom(n2) )
            y.append(getNextRandom(n2) )
            x2.append(getNextRandom(n2) )
            y2.append(getNextRandom(n2) )
        
        RAND1.append(x)
        RAND2.append(y)
        RAND3.append(x2)
        RAND4.append(y2)

    res = gm_eval_honest(v1, C12, C2, n2, RAND1, RAND2,RAND3,RAND4)    
    assert(res != None)
    assert( (v2 <= v1) == compare_leq_honest(res, (p2, q2)) )


    timings = list()
    print "ProofShuffle timings...",
    sys.stdout.flush()
    for i in xrange(10):
        startTime = time.time()
        proof = compute_proof_shuffle(res,n2)
        timings.append(time.time()-startTime)
    avg = numpy.average(timings)
    rstd = 100*numpy.std(timings)/avg
    print "Avg:",str(round(1000*avg,3))+"ms","rel. std. dev.:",str(round(rstd,2)),"%"

    
def compute_proof_shuffle(res, n2):   
    AEpermutation_description, AEpermutation, AEreencrypt_factors = compute_permutation(res, n2)
    AM_permutations = dict()
    ME_permutations = dict()
    for i in xrange(40):
        AM = compute_permutation(res, n2)
        AM_permutations[i]= AM
        AMpermutation_description, AMpermutation, AMreencrypt_factors = AM

        MEpermutation_description = dict()
        MEpermutation = dict()
        MEreencrypt_factors = dict()
          
        for j in xrange(len(res)):
            MEpermutation_description[AMpermutation_description[j]] = AEpermutation_description[j]
            
        for j in xrange(len(res)):
            rs = dict()
            and_encryptions = dict()
            for k in xrange(40):
                r1 = AEreencrypt_factors[j][k]
                r2 = AMreencrypt_factors[j][k]
                r = divm(r1, r2, n2)
                rs[k] = r
                rsquare = powmod(r,2,n2)
                reencryption = (rsquare * AMpermutation[j][k]  ) % n2
                and_encryptions[k] = reencryption
            
            MEpermutation[MEpermutation_description[j]] = (and_encryptions)
            MEreencrypt_factors[j] = (rs)
            
        ME_permutations[i]=( (MEpermutation_description, MEpermutation, MEreencrypt_factors)
        )

    proof = dict()
    hash_input = dict()
    hash_input[0] = (AEpermutation)
    for i in xrange(40):
        hash_input[i+1] = (  ((AM_permutations[i][1]), (ME_permutations[i][1]))  )
    h = hash_flat(hash_input)
    bitstring = format(int(h,16),'0256b')
    
    proof[0] = (hash_input)
    
    for i in xrange(40):
        if (bitstring[i] == "0"):
            AMpermutation_description, AMpermutation, AMreencrypt_factors = AM_permutations[i]       
            proof[i+1] = ( (AMpermutation_description,AMreencrypt_factors))
        else:
            MEpermutation_description, MEpermutation, MEreencrypt_factors = ME_permutations[i]
            proof[i+1] =( (MEpermutation_description, MEreencrypt_factors))

    return proof

def compute_permutation(res, n):
    #pdb.set_trace()
    seed = getNextRandom(n)
    permutation_description = permute(len(res), seed)
    output_permutation = dict()
    reencrypt_factors = list()
    for i in xrange(len(res)):
        rs = list()
        and_encryptions = dict()
        for j in xrange(40):
            r = getNextRandom(n)
            rs.append(r)
            rsquare = powmod(r,2,n)
            reencryption = (rsquare * (res[i])[j]) %n
            and_encryptions[j] = (reencryption)
            
        output_permutation[permutation_description[i]]  = and_encryptions    
        reencrypt_factors.append(rs)
    return permutation_description, output_permutation, reencrypt_factors    


def permute(length,mySeed): #Algorithm P
    rnd.seed(mySeed)
    permutation = dict()
    for i in xrange(length):
        permutation[i] = i

    for i in xrange(length-1):
        index = rnd.randint(i,length-1)
        swap = permutation[i]
        permutation[i] = permutation[index]
        permutation[index] = swap
        
    return permutation

def test_proof_enc():
    

    computeTimings = list()
    verifyTimings = list()
    print "ProofEnc timings...",
    sys.stdout.flush()
    for i in xrange(10):
        keys1 = generate_keys()    
        n1 = keys1['pub']
        p1, q1 = keys1['priv']
        v1 = mpz(random.randint(0, 2**31-1))
        R1 = rand32(n1)
        C1 = encrypt_gm_coin(v1, n1,R1)
        startTime = time.time()
        proof = compute_proof_enc(C1,n1,R1)
        computeTimings.append(time.time()-startTime)
        startTime = time.time()
        verify_proof_enc(proof)
        verifyTimings.append(time.time()-startTime)
    avg = numpy.average(computeTimings)
    rstd = 100*numpy.std(computeTimings)/avg
    print "Avg:",str(round(1000*avg,3))+"ms","rel. std. dev.:",str(round(rstd,2)),"%"
    avg = numpy.average(verifyTimings)
    rstd = 100*numpy.std(verifyTimings)/avg
    print "VerifyProofEnc timings...Avg:",str(round(1000*avg,3))+"ms","rel. std. dev.:",str(round(rstd,2)),"%"


def verify_proof_enc(proof):
    n1 = proof[0]
    C1 = proof[1]
    R1T4S = proof[2]
    h = hash_flat(R1T4S)
    bitstring = format(int(h,16),'0256b')

    success = True
    for i in xrange(40):
        q = int(bitstring[i])
        
        proof_per_bit = proof[i+3]
        for j in xrange(len(C1)):
            A = R1T4S[i][j]
            RHS = (A * powmod(C1[j],2*q,n1))  %n1
            R = proof_per_bit[j]
            LHS = powmod(R,4,n1)
            if LHS!=RHS:
                success = False
            
    return success
            
def compute_proof_enc(C1,n1,R1):
    R1S = list()
    R1T4S = list()
    for i in xrange(40):
        R1S_per_bit = list()
        R1T4S_per_bit = list()
        for j in xrange(len(C1)):
            r_1 = getNextRandom(n1)
            R1S_per_bit.append(r_1)
            R1T4S_per_bit.append(powmod(r_1,4,n1))

        R1S.append(R1S_per_bit)
        R1T4S.append(R1T4S_per_bit)
        
    h = hash_flat(R1T4S)
    bitstring = format(int(h,16),'0256b')

    proof = list()
    proof.append(n1)
    proof.append(C1)
    proof.append(R1T4S)

    for i in xrange(40):
        proof_per_bit = list()
        q = int(bitstring[i])
        for j in xrange(len(C1)):
            R = (powmod(R1[j],q,n1) * R1S[i][j])%n1  
            proof_per_bit.append(R)
        
        proof.append(proof_per_bit)
        
    return proof
    
def test_proofs():
    strain_main()
    test_dlog_eq()
    test_gm_bit_and()
    test_proof_shuffle()
    test_shuffle_verify()
    test_proof_enc()
    
test_proofs()

